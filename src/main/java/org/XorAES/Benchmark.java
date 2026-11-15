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
                case "3" -> runBenchmarkAll();
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

        // 1. Choose XOR Variant
        System.out.println("Select XOR implementation variant:");
        System.out.println("  [1] Native XOR (^)");
        System.out.println("  [2] Boolean Identity ((a|b) & ~(a&b))");
        System.out.println("  [3] Arithmetic Identity (a+b - 2*(a&b))");
        System.out.println("  [4] Lookup Table (256x256 precomputed)");
        System.out.print("Select variant (1-4) [default 1]: ");
        String varChoice = scanner.nextLine().trim();
        ByteOp op = pick(varChoice.isEmpty() ? "1" : varChoice);
        System.out.println("Using: " + op.name());

        // 2. Input Key
        System.out.print("\nEnter 16-byte key in hex (32 chars) or text (press Enter for default key): ");
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

        // 3. Input Plaintext
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

        AesCipher cipher = new AesCipher(op, keyBytes);

        // Apply PKCS#7 padding if not a raw 16-byte hex block
        byte[] paddedInput = isRawHexBlock ? plainBytes : addPkcs7Padding(plainBytes);
        byte[] cipherBytes = new byte[paddedInput.length];

        // Encrypt
        long encStart = System.nanoTime();
        for (int i = 0; i < paddedInput.length; i += 16) {
            byte[] inBlock = new byte[16];
            byte[] outBlock = new byte[16];
            System.arraycopy(paddedInput, i, inBlock, 0, 16);
            cipher.encryptBlock(inBlock, outBlock);
            System.arraycopy(outBlock, 0, cipherBytes, i, 16);
        }
        long encElapsed = System.nanoTime() - encStart;

        // Decrypt
        byte[] decryptedPadded = new byte[cipherBytes.length];
        long decStart = System.nanoTime();
        for (int i = 0; i < cipherBytes.length; i += 16) {
            byte[] inBlock = new byte[16];
            byte[] outBlock = new byte[16];
            System.arraycopy(cipherBytes, i, inBlock, 0, 16);
            cipher.decryptBlock(inBlock, outBlock);
            System.arraycopy(outBlock, 0, decryptedPadded, i, 16);
        }
        long decElapsed = System.nanoTime() - decStart;

        byte[] recoveredBytes = isRawHexBlock ? decryptedPadded : removePkcs7Padding(decryptedPadded);
        String recoveredText = new String(recoveredBytes, StandardCharsets.UTF_8);

        // Display results
        System.out.println("\n=======================================================");
        System.out.println("                 ENCRYPTION RESULTS                    ");
        System.out.println("=======================================================");
        System.out.println("XOR Variant        : " + op.name());
        System.out.println("AES Key (Hex)      : " + Verifier.toHex(keyBytes));
        if (!isRawHexBlock) {
            System.out.println("Input (Text)       : " + plainInput);
        }
        System.out.println("Input (Hex)        : " + Verifier.toHex(plainBytes) + " (" + plainBytes.length + " bytes)");
        if (!isRawHexBlock) {
            System.out.println("Padded (Hex)       : " + Verifier.toHex(paddedInput) + " (" + paddedInput.length + " bytes)");
        }
        System.out.println("Ciphertext (Hex)   : " + Verifier.toHex(cipherBytes));
        System.out.println("Ciphertext (Base64): " + Base64.getEncoder().encodeToString(cipherBytes));
        System.out.println("Encryption Latency : " + encElapsed + " ns (" + (paddedInput.length / 16) + " block(s))");

        System.out.println("\n-------------------------------------------------------");
        System.out.println("                 DECRYPTION VERIFICATION               ");
        System.out.println("-------------------------------------------------------");
        System.out.println("Decrypted (Hex)    : " + Verifier.toHex(recoveredBytes));
        if (!isRawHexBlock) {
            System.out.println("Decrypted (Text)   : " + recoveredText);
        }
        System.out.println("Decryption Latency : " + decElapsed + " ns");
        boolean matches = Arrays.equals(plainBytes, recoveredBytes);
        System.out.println("Integrity Check    : " + (matches ? "SUCCESS (Exact match)" : "FAILED (Mismatch)"));
        System.out.println("=======================================================\n");
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

    private static void runBenchmarkSingle(ByteOp op) {
        System.out.println("Selected XOR variant: " + op.name());
        boolean passed = Verifier.runAll(op);
        System.out.println("Verification: " + (passed ? "PASS" : "FAIL"));
        if (!passed) return;

        executeBenchmark(op);
    }

    private static void runBenchmarkAll() {
        ByteOp[] ops = {
                new NativeXorOp(),
                new BooleanXorOp(),
                new ArithXorOp(),
                new LookUpXorOp()
        };

        System.out.println("\n=======================================================");
        System.out.println("           Running Benchmark Suite (1 MiB Buffer)       ");
        System.out.println("=======================================================");

        for (ByteOp op : ops) {
            System.out.println("\n-------------------------------------------------------");
            System.out.println("Variant: " + op.name());
            executeBenchmark(op);
        }
    }

    private static void executeBenchmark(ByteOp op) {
        byte[] key = new byte[16];
        new Random(42).nextBytes(key);

        byte[] plainBuffer = new byte[BUFFER_SIZE];
        new Random(1337).nextBytes(plainBuffer);

        byte[] cipherBuffer = new byte[BUFFER_SIZE];
        byte[] decryptedBuffer = new byte[BUFFER_SIZE];

        AesCipher cipher = new AesCipher(op, key);
        int blocks = BUFFER_SIZE / 16;

        // Warmup
        for (int r = 0; r < WARMUP_ROUNDS; r++) {
            runEncryption(cipher, plainBuffer, cipherBuffer);
            runDecryption(cipher, cipherBuffer, decryptedBuffer);
        }

        // Measure Encryption
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

        // Measure Decryption
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

        double avgEncryptNs = (double) totalEncryptNs / MEASURE_ROUNDS;
        double avgDecryptNs = (double) totalDecryptNs / MEASURE_ROUNDS;

        double encryptNsPerBlock = avgEncryptNs / blocks;
        double decryptNsPerBlock = avgDecryptNs / blocks;

        double encryptMBps = ((double) BUFFER_SIZE / (1024 * 1024)) / (avgEncryptNs / 1_000_000_000.0);
        double decryptMBps = ((double) BUFFER_SIZE / (1024 * 1024)) / (avgDecryptNs / 1_000_000_000.0);

        System.out.printf("Encrypt: %.2f ns/block | %.2f MB/s (min: %.2f ns/block)%n",
                encryptNsPerBlock, encryptMBps, (double) minEncryptNs / blocks);
        System.out.printf("Decrypt: %.2f ns/block | %.2f MB/s (min: %.2f ns/block)%n",
                decryptNsPerBlock, decryptMBps, (double) minDecryptNs / blocks);
        System.out.println("Checksums: Encrypt=" + encryptChecksum + ", Decrypt=" + decryptChecksum);
    }

    private static long runEncryption(AesCipher cipher, byte[] in, byte[] out) {
        byte[] inBlock = new byte[16];
        byte[] outBlock = new byte[16];
        long checksum = 0;

        for (int offset = 0; offset < in.length; offset += 16) {
            System.arraycopy(in, offset, inBlock, 0, 16);
            cipher.encryptBlock(inBlock, outBlock);
            System.arraycopy(outBlock, 0, out, offset, 16);
            for (byte b : outBlock) checksum += b;
        }
        return checksum;
    }

    private static long runDecryption(AesCipher cipher, byte[] in, byte[] out) {
        byte[] inBlock = new byte[16];
        byte[] outBlock = new byte[16];
        long checksum = 0;

        for (int offset = 0; offset < in.length; offset += 16) {
            System.arraycopy(in, offset, inBlock, 0, 16);
            cipher.decryptBlock(inBlock, outBlock);
            System.arraycopy(outBlock, 0, out, offset, 16);
            for (byte b : outBlock) checksum += b;
        }
        return checksum;
    }
}