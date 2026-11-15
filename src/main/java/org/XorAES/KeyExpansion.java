package org.XorAES;

public final class KeyExpansion {
    private final ByteOp byteOp;

    public KeyExpansion(ByteOp byteOp) {
        if(byteOp==null)
            throw new IllegalArgumentException("byte Operation cannot be null");
        this.byteOp = byteOp;
    }

    public int[] expand(byte[] key16) {
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("AES-128 key must be 16 bytes");
        }

        int[] expanded = new int[176];

        // Copy the original 16-byte key into the start.
        for (int i = 0; i < 16; i++) {
            expanded[i] = key16[i] & 0xFF;
        }

        int bytesGenerated = 16;
        int rconIndex = 0;
        int[] temp = new int[4];

        while (bytesGenerated < expanded.length) {
            // Copy the previous 4-byte word.
            for (int i = 0; i < 4; i++) {
                temp[i] = expanded[bytesGenerated - 4 + i];
            }

            // Apply the key-schedule core once every 16 bytes.
            if (bytesGenerated % 16 == 0) {
                // RotWord: rotate left by one byte.
                int first = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = first;

                // SubWord: substitute each byte using the S-box.
                for (int i = 0; i < 4; i++) {
                    temp[i] = Table.SBOX[temp[i]];
                }

                // Apply this round's constant to the first byte.
                temp[0] = byteOp.combine(temp[0], Table.RCON[rconIndex]);
                rconIndex++;
            }

            // XOR each byte with the corresponding byte 16 positions earlier.
            for (int i = 0; i < 4; i++) {
                expanded[bytesGenerated] =
                        byteOp.combine(expanded[bytesGenerated - 16], temp[i]);
                bytesGenerated++;
            }
        }

        return expanded;
    }
}
