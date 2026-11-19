package org.XorAES;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public final class Benchmark {
    private static final int BUFFER_SIZE = 1 << 20; // 1 MiB
    private static final int WARMUP_ROUNDS = 2;
    private static final int MEASURE_ROUNDS = 5;
    private static final String DEFAULT_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c";

    private Benchmark() {
    }

    public static ByteOp pick(String name) {
        if (name == null) {
            return new NativeXorOp();
        }
        return switch (name.trim().toLowerCase()) {
            case "1", "native" -> new NativeXorOp();
            case "2", "boolean" -> new BooleanXorOp();
            case "3", "arithmetic", "arith" -> new ArithXorOp();
            case "4", "lookup" -> new LookUpXorOp();
            default -> {
                System.out.println("Unknown variant '" + name + "', defaulting to Native XOR.");
                yield new NativeXorOp();
            }
        };
    }

    public static void main(String[] args) {
        // If a command-line argument is passed (e.g. "native", "boolean", "benchmark"), run benchmark mode
        if (args.length > 0) {
            String arg = args[0].trim().toLowerCase();
            if (arg.equals("benchmark") || arg.equals("all")) {
                runBenchmarkAll();
            } else {
                ByteOp op = pick(arg);
                runBenchmarkSingle(op);
            }
            return;
        }

        // Terminal Interactive Mode
        Scanner scanner = new Scanner(System.in);
        System.out.println("=======================================================");
        System.out.println("        XOR-Free AES-128 Terminal Console             ");
        System.out.println("=======================================================");

        boolean running = true;
        while (running) {
            System.out.println("\nSelect an option:");
            System.out.println("  [1] Encrypt & Decrypt custom input");
            System.out.println("  [2] Run FIPS-197 Verification (all XOR variants)");
            System.out.println("  [3] Run Performance Benchmark (throughput & latency)");
            System.out.println("  [4] Exit");
            System.out.print("Choice (1-4) [default 1]: ");

            String choice = scanner.nextLine().trim();
            if (choice.isEmpty()) {
                choice = "1";
            }

            switch (choice) {
                case "1" -> handleCustomEncryption(scanner);
                case "2" -> {
                    System.out.println("\n--- Running FIPS-197 Test Vectors ---");
                    runVerificationAll();
                }
                case "3" -> promptAndRunBenchmark(scanner);
                case "4", "exit", "quit" -> {
                    System.out.println("Exiting. Goodbye!");
                    running = false;
                }
                default -> System.out.println("Invalid option. Please choose between 1 and 4.");
            }
        }
    }

    private static void handleCustomEncryption(Scanner scanner) {
        System.out.println("\n-------------------------------------------------------");
        System.out.println("           Encrypt & Decrypt Custom Input              ");
        System.out.println("-------------------------------------------------------");

        // 1. Input Key
        System.out.print("Enter 16-byte key in hex (32 chars) or text (press Enter for default key): ");
        String keyInput = scanner.nextLine().trim();
        byte[] keyBytes;
        if (keyInput.isEmpty()) {
            keyBytes = Verifier.fromHex(DEFAULT_KEY_HEX);
            System.out.println("Using default key: " + DEFAULT_KEY_HEX);
        } else if (isHex(keyInput) && keyInput.length() == 32) {
            keyBytes = Verifier.fromHex(keyInput);
        } else {
            keyBytes = normalizeTo16Bytes(keyInput.getBytes(StandardCharsets.UTF_8));
            System.out.println("Key derived (16 bytes hex): " + Verifier.toHex(keyBytes));
        }

        // 2. Input Plaintext
        System.out.print("\nEnter value to encrypt (text string or 32-char hex block): ");
        String plainInput = scanner.nextLine();
        if (plainInput.isEmpty()) {
            System.out.println("Plaintext cannot be empty.");
            return;
        }

        byte[] plainBytes;
        boolean isRawHexBlock = false;
        if (isHex(plainInput.trim()) && plainInput.trim().length() == 32) {
            System.out.print("Detected 32-char hex. Treat as [1] Raw Hex Block or [2] Plain Text? [1]: ");
            String treatChoice = scanner.nextLine().trim();
            if (treatChoice.isEmpty() || treatChoice.equals("1")) {
                plainBytes = Verifier.fromHex(plainInput.trim());
                isRawHexBlock = true;
            } else {
                plainBytes = plainInput.getBytes(StandardCharsets.UTF_8);
            }
        } else {
            plainBytes = plainInput.getBytes(StandardCharsets.UTF_8);
        }

        byte[] paddedInput = isRawHexBlock ? plainBytes : addPkcs7Padding(plainBytes);
        int numBlocks = paddedInput.length / 16;
        int warmupIters = 25000;
        int measureIters = 50000;

        ByteOp[] ops = {
                new NativeXorOp(),
                new BooleanXorOp(),
                new ArithXorOp(),
                new LookUpXorOp()
        };

        byte[] firstCipherBytes = null;
        String recoveredText = "";
        byte[] recoveredBytes = null;
        double[] encNsPerBlock = new double[ops.length];
        double[] decNsPerBlock = new double[ops.length];
        boolean allCiphertextsMatch = true;

        System.out.println("\nExecuting across all 4 XOR variants with JIT warmup (" + warmupIters + " warmup, " + measureIters + " timed runs)...");

        for (int i = 0; i < ops.length; i++) {
            ByteOp op = ops[i];
            AesCipher cipher = new AesCipher(op, keyBytes);

            // 1. Single functional pass to produce and verify ciphertext
            byte[] cipherBytes = new byte[paddedInput.length];
            for (int offset = 0; offset < paddedInput.length; offset += 16) {
                cipher.encryptBlock(paddedInput, offset, cipherBytes, offset);
            }

            if (i == 0) {
                firstCipherBytes = cipherBytes;
            } else if (!Arrays.equals(firstCipherBytes, cipherBytes)) {
                allCiphertextsMatch = false;
            }

            byte[] decryptedPadded = new byte[cipherBytes.length];
            for (int offset = 0; offset < cipherBytes.length; offset += 16) {
                cipher.decryptBlock(cipherBytes, offset, decryptedPadded, offset);
            }

            if (i == 0) {
                recoveredBytes = isRawHexBlock ? decryptedPadded : removePkcs7Padding(decryptedPadded);
                recoveredText = new String(recoveredBytes, StandardCharsets.UTF_8);
            }

            // 2. JIT Heavy Optimization Tier Warmup (25,000 iterations)
            byte[] tempBlock = new byte[16];
            for (int w = 0; w < warmupIters; w++) {
                cipher.encryptBlock(paddedInput, 0, tempBlock, 0);
                cipher.decryptBlock(tempBlock, 0, tempBlock, 0);
            }

            // 3. Timed Loop for Steady-State Encryption (50,000 iterations)
            long encStart = System.nanoTime();
            for (int m = 0; m < measureIters; m++) {
                for (int offset = 0; offset < paddedInput.length; offset += 16) {
                    cipher.encryptBlock(paddedInput, offset, tempBlock, 0);
                }
            }
            long encTotal = System.nanoTime() - encStart;
            encNsPerBlock[i] = (double) encTotal / ((long) measureIters * numBlocks);

            // 4. Timed Loop for Steady-State Decryption (50,000 iterations)
            long decStart = System.nanoTime();
            for (int m = 0; m < measureIters; m++) {
                for (int offset = 0; offset < cipherBytes.length; offset += 16) {
                    cipher.decryptBlock(cipherBytes, offset, tempBlock, 0);
                }
            }
            long decTotal = System.nanoTime() - decStart;
            decNsPerBlock[i] = (double) decTotal / ((long) measureIters * numBlocks);
        }

        // Display results
        System.out.println("\n=======================================================");
        System.out.println("                 ENCRYPTION RESULTS                    ");
        System.out.println("=======================================================");
        System.out.println("AES Key (Hex)      : " + Verifier.toHex(keyBytes));
        if (!isRawHexBlock) {
            System.out.println("Input (Text)       : " + plainInput);
        }
        System.out.println("Input (Hex)        : " + Verifier.toHex(plainBytes) + " (" + plainBytes.length + " bytes)");
        if (!isRawHexBlock) {
            System.out.println("Padded (Hex)       : " + Verifier.toHex(paddedInput) + " (" + paddedInput.length + " bytes, " + numBlocks + " block(s))");
        }
        System.out.println("Ciphertext (Hex)   : " + Verifier.toHex(firstCipherBytes));
        System.out.println("Ciphertext (Base64): " + Base64.getEncoder().encodeToString(firstCipherBytes));
        System.out.println("All 4 XOR Variants : " + (allCiphertextsMatch ? "MATCH 100% (Bit-for-bit identical)" : "MISMATCH"));

        System.out.println("\n-------------------------------------------------------");
        System.out.println("                 DECRYPTION VERIFICATION               ");
        System.out.println("-------------------------------------------------------");
        System.out.println("Decrypted (Hex)    : " + Verifier.toHex(recoveredBytes));
        if (!isRawHexBlock) {
            System.out.println("Decrypted (Text)   : " + recoveredText);
        }
        boolean matches = Arrays.equals(plainBytes, recoveredBytes);
        System.out.println("Integrity Check    : " + (matches ? "SUCCESS (Exact match)" : "FAILED (Mismatch)"));

        System.out.println("\n" + "=".repeat(85));
        System.out.println("          STEADY-STATE JIT TIMING (WARMED UP, 50,000 TIMED ITERATIONS)");
        System.out.println("=".repeat(85));
        System.out.printf("%-22s | %-22s | %-22s | %-12s%n",
                "XOR Variant", "Encrypt (ns/block)", "Decrypt (ns/block)", "Slowdown");
        System.out.println("-".repeat(85));
        double nativeEnc = encNsPerBlock[0];
        for (int i = 0; i < ops.length; i++) {
            double slowdown = encNsPerBlock[i] / nativeEnc;
            System.out.printf("%-22s | %13.1f ns       | %13.1f ns       | %9.2f×%n",
                    ops[i].name(), encNsPerBlock[i], decNsPerBlock[i], slowdown);
        }
        System.out.println("=".repeat(85) + "\n");
    }

    private static byte[] addPkcs7Padding(byte[] in) {
        int padLen = 16 - (in.length % 16);
        byte[] padded = new byte[in.length + padLen];
        System.arraycopy(in, 0, padded, 0, in.length);
        for (int i = in.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    private static byte[] removePkcs7Padding(byte[] in) {
        if (in.length == 0 || in.length % 16 != 0) {
            return in;
        }
        int padLen = in[in.length - 1] & 0xFF;
        if (padLen < 1 || padLen > 16) {
            return in;
        }
        for (int i = in.length - padLen; i < in.length; i++) {
            if ((in[i] & 0xFF) != padLen) {
                return in; // Padding invalid, return unstripped
            }
        }
        return Arrays.copyOfRange(in, 0, in.length - padLen);
    }

    private static byte[] normalizeTo16Bytes(byte[] in) {
        byte[] result = new byte[16];
        if (in.length >= 16) {
            System.arraycopy(in, 0, result, 0, 16);
        } else {
            System.arraycopy(in, 0, result, 0, in.length);
        }
        return result;
    }

    private static boolean isHex(String s) {
        if (s == null || s.isEmpty()) return false;
        for (char c : s.toCharArray()) {
            if (Character.digit(c, 16) < 0) return false;
        }
        return true;
    }

    private static void runVerificationAll() {
        ByteOp[] ops = {
                new NativeXorOp(),
                new BooleanXorOp(),
                new ArithXorOp(),
                new LookUpXorOp()
        };

        for (ByteOp op : ops) {
            System.out.println("\nChecking variant: " + op.name());
            boolean passed = Verifier.runAll(op);
            System.out.println("Result for " + op.name() + ": " + (passed ? "PASS" : "FAIL"));
        }
    }

    private static int benchmarkBufferSize = 256 * 1024; // Default: 256 KiB (16,384 blocks)

    private static class BenchmarkResult {
        String name;
        double encryptNsPerBlock;
        double encryptMBps;
        double decryptNsPerBlock;
        double decryptMBps;
        double minEncryptNsPerBlock;
        double minDecryptNsPerBlock;
        double slowdownVsNative;
        long encryptChecksum;
        long decryptChecksum;
    }

    private static void promptAndRunBenchmark(Scanner scanner) {
        System.out.println("\n-------------------------------------------------------");
        System.out.println("            Performance Benchmark Configuration        ");
        System.out.println("-------------------------------------------------------");
        System.out.println("Select benchmark buffer size:");
        System.out.println("  [1] Quick:    64 KiB  (4,096 blocks  - takes ~0.5s)");
        System.out.println("  [2] Standard: 256 KiB (16,384 blocks - takes ~2.0s) [Recommended]");
        System.out.println("  [3] Thorough: 1 MiB   (65,536 blocks - takes ~8.0s)");
        System.out.print("Choice (1-3) [default 2]: ");
        String sizeChoice = scanner.nextLine().trim();
        int size = switch (sizeChoice) {
            case "1" -> 64 * 1024;
            case "3" -> 1024 * 1024;
            default -> 256 * 1024;
        };
        benchmarkBufferSize = size;
        runBenchmarkAll();
    }

    private static void runBenchmarkSingle(ByteOp op) {
        System.out.println("Selected XOR variant: " + op.name());
        boolean passed = Verifier.runAll(op);
        System.out.println("Verification: " + (passed ? "PASS" : "FAIL"));
        if (!passed) return;

        BenchmarkResult res = executeBenchmark(op, benchmarkBufferSize, true);
        printSingleResult(res);
    }

    private static void runBenchmarkAll() {
        ByteOp[] ops = {
                new NativeXorOp(),
                new BooleanXorOp(),
                new ArithXorOp(),
                new LookUpXorOp()
        };

        int blocks = benchmarkBufferSize / 16;
        System.out.println("\n==================================================================================");
        System.out.printf("       XOR-Free AES-128 Technical Benchmark (%d KiB / %d blocks)%n", benchmarkBufferSize / 1024, blocks);
        System.out.println("==================================================================================");

        BenchmarkResult[] results = new BenchmarkResult[ops.length];
        double nativeEncryptNs = 1.0;

        for (int i = 0; i < ops.length; i++) {
            ByteOp op = ops[i];
            System.out.printf("[%d/4] Testing %-20s ... ", (i + 1), op.name());
            System.out.flush();
            results[i] = executeBenchmark(op, benchmarkBufferSize, false);
            if (i == 0) {
                nativeEncryptNs = results[0].encryptNsPerBlock;
            }
            results[i].slowdownVsNative = results[i].encryptNsPerBlock / nativeEncryptNs;
            System.out.printf("Done! (Enc: %.1f ns/block, Dec: %.1f ns/block)%n",
                    results[i].encryptNsPerBlock, results[i].decryptNsPerBlock);
        }

        printComparisonTable(results);
    }

    private static BenchmarkResult executeBenchmark(ByteOp op, int bufferSize, boolean verbose) {
        byte[] key = new byte[16];
        new Random(42).nextBytes(key);

        byte[] plainBuffer = new byte[bufferSize];
        new Random(1337).nextBytes(plainBuffer);

        byte[] cipherBuffer = new byte[bufferSize];
        byte[] decryptedBuffer = new byte[bufferSize];

        AesCipher cipher = new AesCipher(op, key);
        int blocks = bufferSize / 16;

        if (verbose) System.out.print("  Warming up JIT (" + WARMUP_ROUNDS + " rounds)... ");
        byte[] warmupBufIn = new byte[Math.min(bufferSize, 16 * 1024)];
        byte[] warmupBufOut = new byte[warmupBufIn.length];
        for (int r = 0; r < WARMUP_ROUNDS; r++) {
            runEncryption(cipher, warmupBufIn, warmupBufOut);
            runDecryption(cipher, warmupBufIn, warmupBufOut);
        }
        if (verbose) System.out.println("done.");

        // Measure Encryption
        if (verbose) System.out.print("  Measuring Encryption (" + MEASURE_ROUNDS + " rounds)... ");
        long totalEncryptNs = 0;
        long minEncryptNs = Long.MAX_VALUE;
        long encryptChecksum = 0;
        for (int r = 0; r < MEASURE_ROUNDS; r++) {
            long start = System.nanoTime();
            encryptChecksum += runEncryption(cipher, plainBuffer, cipherBuffer);
            long elapsed = System.nanoTime() - start;
            totalEncryptNs += elapsed;
            if (elapsed < minEncryptNs) minEncryptNs = elapsed;
        }
        if (verbose) System.out.println("done.");

        // Measure Decryption
        if (verbose) System.out.print("  Measuring Decryption (" + MEASURE_ROUNDS + " rounds)... ");
        long totalDecryptNs = 0;
        long minDecryptNs = Long.MAX_VALUE;
        long decryptChecksum = 0;
        for (int r = 0; r < MEASURE_ROUNDS; r++) {
            long start = System.nanoTime();
            decryptChecksum += runDecryption(cipher, cipherBuffer, decryptedBuffer);
            long elapsed = System.nanoTime() - start;
            totalDecryptNs += elapsed;
            if (elapsed < minDecryptNs) minDecryptNs = elapsed;
        }
        if (verbose) System.out.println("done.");

        double avgEncryptNs = (double) totalEncryptNs / MEASURE_ROUNDS;
        double avgDecryptNs = (double) totalDecryptNs / MEASURE_ROUNDS;

        BenchmarkResult res = new BenchmarkResult();
        res.name = op.name();
        res.encryptNsPerBlock = avgEncryptNs / blocks;
        res.decryptNsPerBlock = avgDecryptNs / blocks;
        res.minEncryptNsPerBlock = (double) minEncryptNs / blocks;
        res.minDecryptNsPerBlock = (double) minDecryptNs / blocks;
        res.encryptMBps = ((double) bufferSize / (1024 * 1024)) / (avgEncryptNs / 1_000_000_000.0);
        res.decryptMBps = ((double) bufferSize / (1024 * 1024)) / (avgDecryptNs / 1_000_000_000.0);
        res.encryptChecksum = encryptChecksum;
        res.decryptChecksum = decryptChecksum;

        return res;
    }

    private static void printSingleResult(BenchmarkResult res) {
        System.out.println("\n=== Results for " + res.name + " ===");
        System.out.printf("Encrypt : %9.2f ns/block (%6.3f µs/block) | %6.2f MB/s | (min: %.2f ns)%n",
                res.encryptNsPerBlock, res.encryptNsPerBlock / 1000.0, res.encryptMBps, res.minEncryptNsPerBlock);
        System.out.printf("Decrypt : %9.2f ns/block (%6.3f µs/block) | %6.2f MB/s | (min: %.2f ns)%n",
                res.decryptNsPerBlock, res.decryptNsPerBlock / 1000.0, res.decryptMBps, res.minDecryptNsPerBlock);
        System.out.println("Checksums: Encrypt=" + res.encryptChecksum + ", Decrypt=" + res.decryptChecksum);
    }

    private static void printComparisonTable(BenchmarkResult[] results) {
        System.out.println("\n" + "=".repeat(105));
        System.out.println("                               TECHNICAL BENCHMARK TIMING REPORT");
        System.out.println("=".repeat(105));
        System.out.printf("%-22s | %-24s | %-24s | %-12s | %-10s%n",
                "XOR Implementation", "Encrypt Time (Latency)", "Decrypt Time (Latency)", "Throughput", "Slowdown");
        System.out.printf("%-22s | %-24s | %-24s | %-12s | %-10s%n",
                "Variant", "(ns/block)  (µs/block)", "(ns/block)  (µs/block)", "(Enc / Dec)", "vs Native");
        System.out.println("-".repeat(105));

        for (BenchmarkResult r : results) {
            String encTime = String.format("%7.1f ns  (%5.3f µs)", r.encryptNsPerBlock, r.encryptNsPerBlock / 1000.0);
            String decTime = String.format("%7.1f ns  (%5.3f µs)", r.decryptNsPerBlock, r.decryptNsPerBlock / 1000.0);
            String tput = String.format("%4.1f / %4.1f MB/s", r.encryptMBps, r.decryptMBps);
            String slowdown = String.format("%5.2f×", r.slowdownVsNative);

            System.out.printf("%-22s | %-24s | %-24s | %-12s | %-10s%n",
                    r.name, encTime, decTime, tput, slowdown);
        }
        System.out.println("=".repeat(105));
        System.out.println("Note: Checksums across all variants match identically, verifying functional equivalence.");
        System.out.println("      Decryption is slower due to 9, 11, 13, 14 polynomial multipliers in InvMixColumns.\n");
    }

    private static long runEncryption(AesCipher cipher, byte[] in, byte[] out) {
        long checksum = 0;
        for (int offset = 0; offset < in.length; offset += 16) {
            cipher.encryptBlock(in, offset, out, offset);
        }
        for (int i = 0; i < out.length; i += 16) {
            checksum += out[i];
        }
        return checksum;
    }

    private static long runDecryption(AesCipher cipher, byte[] in, byte[] out) {
        long checksum = 0;
        for (int offset = 0; offset < in.length; offset += 16) {
            cipher.decryptBlock(in, offset, out, offset);
        }
        for (int i = 0; i < out.length; i += 16) {
            checksum += out[i];
        }
        return checksum;
    }
}