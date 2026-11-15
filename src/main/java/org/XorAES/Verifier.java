package org.XorAES;

import org.XorAES.AesCipher;
import org.XorAES.ByteOp;

public final class Verifier {
    private Verifier() {
        // Utility class; use the static runAll method.
    }

    public static boolean runAll(ByteOp op) {
        System.out.println("runAll: starting");

        System.out.println("runAll: checking Appendix B");
        boolean appendixB = checkVector(
                op,
                "2b7e151628aed2a6abf7158809cf4f3c",
                "3243f6a8885a308d313198a2e0370734",
                "3925841d02dc09fbdc118597196a0b32");
        System.out.println("runAll: Appendix B returned " + appendixB);

        System.out.println("runAll: checking Appendix C.1");
        boolean appendixC1 = checkVector(
                op,
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff",
                "69c4e0d86a7b0430d8cdb78070b4c55a");
        System.out.println("runAll: Appendix C.1 returned " + appendixC1);

        System.out.println("runAll: finished");
        return appendixB && appendixC1;
    }

    private static boolean checkVector(
            ByteOp op, String keyHex, String plaintextHex, String ciphertextHex) {

        System.out.println("checkVector: converting hex");
        byte[] key = fromHex(keyHex);
        byte[] plaintext = fromHex(plaintextHex);
        byte[] expectedCiphertext = fromHex(ciphertextHex);

        System.out.println("checkVector: constructing cipher");
        AesCipher cipher = new AesCipher(op, key);

        System.out.println("checkVector: encrypting");
        byte[] actualCiphertext = new byte[16];
        cipher.encryptBlock(plaintext, actualCiphertext);

        System.out.println("checkVector: comparing ciphertext");
        if (!sameBytes(actualCiphertext, expectedCiphertext)) {
            System.out.println("Expected: " + toHex(expectedCiphertext));
            System.out.println("Actual:   " + toHex(actualCiphertext));
            return false;
        }

        System.out.println("checkVector: decrypting");
        byte[] recoveredPlaintext = new byte[16];
        cipher.decryptBlock(expectedCiphertext, recoveredPlaintext);

        System.out.println("checkVector: comparing plaintext");
        return sameBytes(recoveredPlaintext, plaintext);
    }

    static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];

        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(hex.charAt(2 * i), 16);
            int low = Character.digit(hex.charAt(2 * i + 1), 16);

            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hexadecimal input");
            }

            bytes[i] = (byte) ((high << 4) | low);
        }

        return bytes;
    }

    private static boolean sameBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xFF));
        }

        return result.toString();
    }
}
