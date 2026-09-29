{
  description = "Nix flake for BPF program developpement";

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
          bpfSource =
            let
              configuredSource = builtins.getEnv "BPF_SRC";
            in
            if configuredSource == "" then "testsBPF/test.c" else configuredSource;
          bpfProgram = pkgs.stdenvNoCC.mkDerivation {
            pname = "testsBPF-test";
            version = "1.0";

            src = ./.;

            nativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ];
            buildInputs = [
              pkgs.libbpf
              pkgs.linuxHeaders
            ];

            buildPhase = ''
              ${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
                -O2 -g -target bpf \
                -I${pkgs.linuxHeaders}/include \
                -I${pkgs.libbpf}/include \
                -c ${bpfSource} -o test.o
            '';

            installPhase = ''
              mkdir -p $out/lib/bpf
              cp test.o $out/lib/bpf/
            '';

            meta = with pkgs.lib; {
              description = "BPF object built from testsBPF/test.c";
              license = licenses.unlicense;
              platforms = platforms.unix;
            };
          };
          loaderSource = pkgs.writeText "load-bpf.c" ''
            #define _GNU_SOURCE
            #include <bpf/libbpf.h>
            #include <errno.h>
            #include <signal.h>
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

            int main(int argc, char **argv)
            {
              const char *defaultObject = "${bpfProgram}/lib/bpf/test.o";
              const char *objectPath = argc > 1 ? argv[1] : defaultObject;
              struct bpf_object *object = NULL;
              struct bpf_program *program = NULL;
              struct bpf_link **links = NULL;
              size_t programCount = 0;
              size_t programIndex = 0;
              int error = 0;

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
                links[programIndex] = bpf_program__attach(program);
                if (!links[programIndex]) {
                  fprintf(stderr, "failed to attach program: %s\n", bpf_program__name(program));
                  error = 1;
                  goto cleanup;
                }

                programIndex++;
              }

              printf("Loaded and attached %zu BPF program(s) from %s\n", programCount, objectPath);
              printf("Press Ctrl-C to detach.\n");

              while (!exiting) {
                pause();
              }

            cleanup:
              if (links) {
                for (size_t index = 0; index < programIndex; index++) {
                  bpf_link__destroy(links[index]);
                }
              }

              free(links);
              bpf_object__close(object);
              return error;
            }
          '';
          loader = pkgs.stdenv.mkDerivation {
            pname = "load-bpf";
            version = "1.0";

            src = loaderSource;

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.libbpf ];

            dontUnpack = true;

            buildPhase = ''
              cc $src -o load-bpf $(pkg-config --cflags --libs libbpf)
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp load-bpf $out/bin/
            '';
          };
        in
        {
          packages = {
            "testsBPF/test.c" = bpfProgram;
            testsBPF-test = bpfProgram;
            load-bpf = loader;
          };

          apps = {
            load-bpf = {
              type = "app";
              program = "${loader}/bin/load-bpf";
            };

            run-testsBPF-test = {
              type = "app";
              program = "${loader}/bin/load-bpf";
            };
          };
        };
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system: (mkSystem system).packages);
      apps = nixpkgs.lib.genAttrs systems (system: (mkSystem system).apps);

      defaultPackage = nixpkgs.lib.genAttrs systems (system: self.packages.${system}."testsBPF/test.c");
    };
}
