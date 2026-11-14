XOR-Free AES-128

A research-oriented implementation of AES-128 in Java that replaces the native XOR operation with alternative XOR-equivalent implementations while preserving the correctness of the AES algorithm. The project explores the impact of XOR substitution on cryptographic operations, performance, and software design. Based on the implementation plan described in XOR-Free AES-128 Implementation Plan.pdf.

Overview

AES relies heavily on XOR operations in:

AddRoundKey
Key Expansion
MixColumns
GF(2⁸) arithmetic

This project abstracts XOR behind a common interface and evaluates multiple XOR-equivalent implementations while keeping the AES logic unchanged.

Implemented XOR variants:

Native XOR (^)
Boolean Identity
(a | b) & ~(a & b)
Arithmetic Identity
a + b - 2 * (a & b)
Lookup Table
Precomputed 256 × 256 XOR lookup table

All variants produce identical ciphertexts and plaintext recovery while exhibiting different performance characteristics.

Objectives
Implement AES-128 encryption and decryption from scratch.
Identify all XOR usage locations within AES.
Replace XOR using alternative equivalent methods.
Verify correctness using FIPS-197 test vectors.
Benchmark encryption and decryption performance.
Analyze security and implementation implications.
Project Structure
xoraes/
│
├── ByteOp.java
├── NativeXorOp.java
├── BooleanXorOp.java
├── ArithXorOp.java
├── LookupXorOp.java
│
├── Tables.java
├── GF256.java
├── KeyExpansion.java
├── AesCipher.java
│
├── Verifier.java
└── Benchmark.java

Core Components
Class	ResponsibilityByteOp	Strategy interface for byte combination
NativeXorOp	Standard XOR implementation
BooleanXorOp	XOR using Boolean algebra
ArithXorOp	XOR using arithmetic identity
LookupXorOp	XOR using lookup table
Tables	AES S-Box, Inverse S-Box, RCON
GF256	Finite field arithmetic
KeyExpansion	AES key schedule
AesCipher	AES encryption/decryption engine
Verifier	Test vector verification
Benchmark	Performance evaluation

Based on the Strategy Design Pattern, the AES implementation remains unchanged while different XOR mechanisms can be swapped dynamically.

AES Flow
Encryption
AddRoundKey

Rounds 1-9:
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey

Round 10:
    SubBytes
    ShiftRows
    AddRoundKey

Decryption
AddRoundKey

Rounds 9-1:
    InvShiftRows
    InvSubBytes
    AddRoundKey
    InvMixColumns

Final Round:
    InvShiftRows
    InvSubBytes
    AddRoundKey

XOR Replacement Strategies
Native XOR
return a ^ b;

Boolean Identity
return ((a | b) & ~(a & b)) & 0xFF;

Arithmetic Identity
return (a + b - 2 * (a & b)) & 0xFF;

Lookup Table
return table[(a << 8) | b] & 0xFF;


All implementations are mathematically equivalent for byte values (0–255).

Verification

The implementation is validated using:

FIPS-197 Appendix B
Item	ValueKey	2b7e151628aed2a6abf7158809cf4f3c
Plaintext	3243f6a8885a308d313198a2e0370734
Ciphertext	3925841d02dc09fbdc118597196a0b32
FIPS-197 Appendix C.1
Item	ValueKey	000102030405060708090a0b0c0d0e0f
Plaintext	00112233445566778899aabbccddeeff
Ciphertext	69c4e0d86a7b0430d8cdb78070b4c55a

Additionally, all XOR substitutes undergo an exhaustive 65,536-pair test against native XOR before integration into AES.

Building the Project
Requirements
Java 17+
JDK installed and configured
Compile
javac xoraes/*.java

Run Verification
java xoraes.Benchmark native


or

java xoraes.Benchmark boolean

java xoraes.Benchmark arithmetic

java xoraes.Benchmark lookup

Benchmarking

The benchmarking process:

Generate a fixed test buffer.
Warm up the JVM.
Run multiple iterations.
Measure:
Encryption time per block
Decryption time per block
Throughput (MB/s)
Compare slowdown against native XOR.
Results Template
Variant	Encrypt Time (ns/block)	Encrypt MB/s	Decrypt Time (ns/block)	Decrypt MB/s	SlowdownNative XOR					1.00×
Boolean Identity					
Arithmetic Identity					
Lookup Table					
Security Notes

Although all XOR-free implementations produce identical AES outputs, implementation details can affect side-channel behavior:

Lookup tables may introduce cache-timing leakage.
Conditional branches in GF arithmetic may reveal timing information.
Boolean and arithmetic variants avoid data-dependent memory access but are not guaranteed constant-time after JIT optimizations.
Production systems should use vetted cryptographic libraries or hardware-accelerated AES (AES-NI).
Expected Findings
Native XOR should be the fastest implementation.
Boolean and arithmetic variants introduce computational overhead.
Lookup-table performance depends heavily on cache behavior.
Decryption is expected to experience greater slowdown due to InvMixColumns complexity.
Future Work
AES-256 implementation
FPGA-based comparison
AES-NI comparison
Additional XOR-free finite field arithmetic techniques
More extensive side-channel analysis
Author

Srujan R Bhat

Academic Project: XOR-Free AES-128 Research and Performance Analysis.

License

This project is intended for educational and research purposes only. Use established cryptographic libraries for production applications.
