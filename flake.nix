{
  description = "Nix flake for BPF program development";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];

      mkSystem =
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;

          # Tous les .c de testsBPF/ -> ["test" "xdpfilter80" ...]
          bpfNames = map (lib.removeSuffix ".c") (
            lib.filter (lib.hasSuffix ".c") (builtins.attrNames (builtins.readDir ./testsBPF))
          );

          mkBpf =
            name:
            pkgs.stdenvNoCC.mkDerivation {
              pname = "bpf-${name}";
              version = "1.0";
              src = ./.;

              nativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ];
              buildInputs = [
                pkgs.libbpf
                pkgs.linuxHeaders
              ];

              buildPhase = ''
                clang -O2 -g -target bpf \
                  -I${pkgs.linuxHeaders}/include \
                  -I${pkgs.libbpf}/include \
                  -c testsBPF/${name}.c -o ${name}.o
              '';

              installPhase = ''
                mkdir -p $out/lib/bpf
                cp ${name}.o $out/lib/bpf/
              '';

              meta.description = "BPF object built from testsBPF/${name}.c";
            };

          bpfPrograms = lib.genAttrs bpfNames mkBpf;

          loaderSource = pkgs.writeText "load-bpf.c" ''
            #define _GNU_SOURCE
            #include <bpf/libbpf.h>
            #include <bpf/bpf.h>
            #include <linux/if_link.h>
            #include <net/if.h>
            #include <errno.h>
            #include <signal.h>
            #include <string.h>
            #include <sys/resource.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <unistd.h>

            static volatile sig_atomic_t exiting = 0;

            static void handleSignal(int signalNumber)
            {
              (void)signalNumber;
              exiting = 1;
            }

            static void usage(const char *name)
            {
              fprintf(stderr, "usage: %s <object.o> [interface] [--skb]\n", name);
              fprintf(stderr, "  interface : requis pour les programmes XDP (ex: eth0, lo)\n");
              fprintf(stderr, "  --skb     : force le mode XDP generique (sans support driver)\n");
            }

            int main(int argc, char **argv)
            {
              const char *objectPath = NULL;
              const char *ifName = NULL;
              unsigned int xdpFlags = 0;
              int ifIndex = 0;
              int xdpAttached = 0;

              struct bpf_object *object = NULL;
              struct bpf_program *program = NULL;
              struct bpf_link **links = NULL;
              size_t programCount = 0;
              size_t programIndex = 0;
              int error = 0;

              for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i], "--skb") == 0) {
                  xdpFlags |= XDP_FLAGS_SKB_MODE;
                } else if (!objectPath) {
                  objectPath = argv[i];
                } else if (!ifName) {
                  ifName = argv[i];
                } else {
                  usage(argv[0]);
                  return 1;
                }
              }

              if (!objectPath) {
                usage(argv[0]);
                return 1;
              }

              if (ifName) {
                ifIndex = if_nametoindex(ifName);
                if (ifIndex == 0) {
                  fprintf(stderr, "unknown interface: %s\n", ifName);
                  return 1;
                }
              }

              signal(SIGINT, handleSignal);
              signal(SIGTERM, handleSignal);

              struct rlimit memlockLimit = { RLIM_INFINITY, RLIM_INFINITY };
              if (setrlimit(RLIMIT_MEMLOCK, &memlockLimit) != 0) {
                perror("setrlimit(RLIMIT_MEMLOCK)");
              }

              object = bpf_object__open_file(objectPath, NULL);
              if (!object) {
                fprintf(stderr, "failed to open BPF object: %s\n", objectPath);
                return 1;
              }

              bpf_object__for_each_program(program, object) {
                programCount++;
              }

              links = calloc(programCount > 0 ? programCount : 1, sizeof(*links));
              if (!links) {
                perror("calloc");
                error = 1;
                goto cleanup;
              }

              error = bpf_object__load(object);
              if (error) {
                fprintf(stderr, "failed to load BPF object: %s\n", objectPath);
                fprintf(stderr, "This usually means the kernel denied BPF loading. Try running as root or with CAP_BPF/CAP_SYS_ADMIN.\n");
                goto cleanup;
              }

              bpf_object__for_each_program(program, object) {
                const char *progName = bpf_program__name(program);

                if (bpf_program__type(program) == BPF_PROG_TYPE_XDP) {
                  if (ifIndex == 0) {
                    fprintf(stderr, "program %s is XDP: an interface name is required\n", progName);
                    error = 1;
                    goto cleanup;
                  }
                  if (xdpAttached) {
                    fprintf(stderr, "only one XDP program can be attached per interface (skipping %s)\n", progName);
                    programIndex++;
                    continue;
                  }

                  error = bpf_xdp_attach(ifIndex, bpf_program__fd(program), xdpFlags, NULL);
                  if (error) {
                    fprintf(stderr, "failed to attach XDP program %s on %s: %s\n",
                            progName, ifName, strerror(-error));
                    goto cleanup;
                  }
                  xdpAttached = 1;
                  printf("XDP program %s attached on %s\n", progName, ifName);
                } else {
                  links[programIndex] = bpf_program__attach(program);
                  if (!links[programIndex]) {
                    fprintf(stderr, "failed to attach program: %s\n", progName);
                    error = 1;
                    goto cleanup;
                  }
                }

                programIndex++;
              }

              printf("Loaded %zu BPF program(s) from %s\n", programCount, objectPath);
              printf("Press Ctrl-C to detach.\n");

              while (!exiting) {
                pause();
              }

            cleanup:
              if (xdpAttached) {
                bpf_xdp_attach(ifIndex, -1, xdpFlags, NULL);
                printf("XDP program detached from %s\n", ifName);
              }

              if (links) {
                for (size_t index = 0; index < programIndex; index++) {
                  if (links[index]) {
                    bpf_link__destroy(links[index]);
                  }
                }
              }

              free(links);
              bpf_object__close(object);
              return error ? 1 : 0;
            }
          '';

          loader = pkgs.stdenv.mkDerivation {
            pname = "load-bpf";
            version = "1.0";
            src = loaderSource;
            dontUnpack = true;

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.libbpf ];

            buildPhase = ''
              cc $src -o load-bpf $(pkg-config --cflags --libs libbpf)
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp load-bpf $out/bin/
            '';
          };

          # Une app par programme : loader + chemin du .o
          mkApp =
            name:
            let
              script = pkgs.writeShellScript "run-${name}" ''
                exec ${loader}/bin/load-bpf ${bpfPrograms.${name}}/lib/bpf/${name}.o "$@"
              '';
            in
            {
              type = "app";
              program = "${script}";
            };
        in
        {
          packages = bpfPrograms // {
            load-bpf = loader;
            default = bpfPrograms.test or (lib.head (lib.attrValues bpfPrograms));
          };

          apps = (lib.genAttrs bpfNames mkApp) // {
            load-bpf = {
              type = "app";
              program = "${loader}/bin/load-bpf";
            };
          };
        };
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system: (mkSystem system).packages);
      apps = nixpkgs.lib.genAttrs systems (system: (mkSystem system).apps);
      devShells = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.bpftools ];
          };
        }
      );
    };
}
