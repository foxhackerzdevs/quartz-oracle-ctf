# Quartz Oracle — Timing Side-Channel Challenge

**Category:** Crypto / Side-channel
**Difficulty:** Medium

A "custom HSM modular exponentiation engine" leaks its RSA private key through timing. Recover the secret number it's protecting.

## Connecting

```bash
nc abhrankan.duckdns.org 9998
```

The server announces `N` and `e` on connect, then accepts hex-encoded ciphertexts, one per line, and responds with its own precisely-measured elapsed computation time for `pow(c, d, N)`.

`N=40723`, `e=65537`.

**Target ciphertext:** `21494`

Recover the secret number `m` such that `pow(m, 65537, 40723) == 21494`.

## A note on scope

This is a teaching-scale challenge (16-bit modulus), not a production-strength crypto CTF. The oracle's design is a real, working Kocher-style timing side-channel -- extra computation time is spent whenever an intermediate value crosses N/2 during modular exponentiation, a simplified analogue of Montgomery multiplication's real data-dependent "extra reduction" step. That part is genuine and scales conceptually to real RSA key sizes.

What doesn't trivially scale is the specific recovery technique demonstrated in the solution: raw bit-by-bit timing recovery at this modulus size has a real, measured error rate well above 50% per bit in practice (confirmed during development, including on real network timing, not just theory) -- solving it requires an error-tolerant approach, not a clean single-pass recovery. That error-tolerant correction step, as implemented, does not remain tractable at realistic (64+ bit) key sizes without significantly more sophisticated statistics than what's demonstrated here. This challenge is scoped honestly to the size where the full technique is proven to work, not inflated to look like a "real" flag-length target.

## Rules

Everything you need is in this repo. No live host beyond the challenge server itself.

Good luck.
