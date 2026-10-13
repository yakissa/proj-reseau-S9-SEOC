#!/usr/bin/env python3
"""Tests fonctionnels de kvstore : SET/DELETE en TCP, GET en TCP et en UDP.

Usage : python3 test_kvstore.py [hôte] [port]
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11211


def tcp(cmd: bytes) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=2) as s:
        s.sendall(cmd)
        data = b""
        while not data.endswith((b"END\r\n", b"STORED\r\n", b"DELETED\r\n",
                                 b"NOT_FOUND\r\n", b"ERROR\r\n")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data


def udp(cmd: bytes, req_id: int = 42) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(struct.pack("!HHHH", req_id, 0, 1, 0) + cmd, (HOST, PORT))
        data, _ = s.recvfrom(65536)
        rid, seq, total, _ = struct.unpack("!HHHH", data[:8])
        assert (rid, seq, total) == (req_id, 0, 1), (rid, seq, total)
        return data[8:]


def check(name, got, expected):
    status = "OK " if got == expected else "ÉCHEC"
    print(f"[{status}] {name}")
    if got != expected:
        print(f"    attendu : {expected!r}\n    obtenu  : {got!r}")
    return got == expected


ok = True
ok &= check("set TCP", tcp(b"set foo 5 0 3\r\nbar\r\n"), b"STORED\r\n")
ok &= check("get TCP", tcp(b"get foo\r\n"), b"VALUE foo 5 3\r\nbar\r\nEND\r\n")
ok &= check("get UDP", udp(b"get foo\r\n"), b"VALUE foo 5 3\r\nbar\r\nEND\r\n")
ok &= check("get UDP absent", udp(b"get nope\r\n"), b"END\r\n")
tcp(b"set k2 0 0 5\r\nhello\r\n")
ok &= check("multiget UDP", udp(b"get foo k2 nope\r\n"),
            b"VALUE foo 5 3\r\nbar\r\nVALUE k2 0 5\r\nhello\r\nEND\r\n")
ok &= check("écrasement", tcp(b"set foo 0 0 4\r\nbaz!\r\nget foo\r\n"),
            b"STORED\r\nVALUE foo 0 4\r\nbaz!\r\nEND\r\n")
ok &= check("delete", tcp(b"delete foo\r\n"), b"DELETED\r\n")
ok &= check("delete absent", tcp(b"delete foo\r\n"), b"NOT_FOUND\r\n")
ok &= check("get après delete", udp(b"get foo\r\n"), b"END\r\n")
ok &= check("commande inconnue", tcp(b"bogus\r\n"), b"ERROR\r\n")

print("\nTous les tests passent." if ok else "\nCertains tests échouent.")
sys.exit(0 if ok else 1)
