#!/usr/bin/env python3
"""
Timing Oracle CTF Server ("Quartz Oracle")

Vulnerable RSA "HSM" that leaks its private exponent through a
Kocher-style timing side channel: extra computation time is spent
whenever an intermediate value exceeds N/2 during modular
exponentiation -- a simplified analogue of Montgomery multiplication's
data-dependent "extra reduction" step in real hardware.

Protocol (one query per line, newline-terminated):
  Request:  hex-encoded ciphertext (integer), e.g. "1a2b3c\\n"
  Response: "<elapsed_seconds>\\n" -- the server's own precise
            wall-clock time spent computing pow(c, d, N)
"""
import socket
import time
import os

HOST = '0.0.0.0'
PORT = int(os.environ.get('ORACLE_PORT', 9998))
MAX_LINE = 4096
IDLE_TIMEOUT = 30.0

N = int(os.environ.get('ORACLE_N', '0'))
D = int(os.environ.get('ORACLE_D', '0'))
E = 65537

BASE_SLEEP = 0.001
SQUARE_PREDICATE_SLEEP = 0.008
MULTIPLY_SLEEP = 0.001
MULTIPLY_PREDICATE_SLEEP = 0.020


def vulnerable_pow(base, exponent, modulus):
    result = 1
    base %= modulus
    for bit in bin(exponent)[2:]:
        result = (result * result) % modulus
        time.sleep(BASE_SLEEP)
        if result > (modulus >> 1):
            time.sleep(SQUARE_PREDICATE_SLEEP)
        if bit == '1':
            result = (result * base) % modulus
            time.sleep(MULTIPLY_SLEEP)
            if result > (modulus >> 1):
                time.sleep(MULTIPLY_PREDICATE_SLEEP)
    return result


def handle_client(conn):
    with conn:
        conn.settimeout(IDLE_TIMEOUT)
        conn.sendall(f"N={N}\ne={E}\n".encode())
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
            if b"\n" not in buf and len(buf) > MAX_LINE:
                conn.sendall(b"ERROR input too long\n")
                return
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                if len(line) > MAX_LINE:
                    conn.sendall(b"ERROR input too long\n")
                    continue
                if line == b"QUIT":
                    return
                try:
                    c = int(line, 16) % N
                except ValueError:
                    conn.sendall(b"ERROR invalid input\n")
                    continue
                t0 = time.perf_counter()
                vulnerable_pow(c, D, N)
                elapsed = time.perf_counter() - t0
                conn.sendall(f"{elapsed:.9f}\n".encode())


def main():
    if N == 0 or D == 0:
        raise SystemExit("Set ORACLE_N and ORACLE_D environment variables before starting.")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Timing oracle listening on {HOST}:{PORT}")
    while True:
        conn = None
        try:
            conn, addr = server.accept()
            handle_client(conn)
        except Exception as e:
            print(f"[!] Error handling connection: {e}")


if __name__ == "__main__":
    main()
