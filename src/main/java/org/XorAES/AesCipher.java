package org.XorAES;

public class AesCipher {
    private final ByteOp byteOp;
    private final GF256 gf;
    private final int[] roundKeys;

    public AesCipher(ByteOp byteOp, byte[] keys) {
        this.byteOp = byteOp;
        this.gf=new GF256(byteOp);
        this.roundKeys = new KeyExpansion(byteOp).expand(keys);
    }

    public void encryptBlock(byte[] input, byte[] output){
        if(input.length!=16 || output.length!=16)
            throw new IllegalArgumentException("AES encrypts exactly one 16-byte block");

        int[] state = new int[16];
        for(int i=0;i<16;i++){
            state[i]=input[i] & 0xFF;
        }
        addRoundKey(state,0);

        for(int round=1;round<=9;round++){
            subBytes(state);
            shiftRows(state);
            mixCoulmns(state);
            addRoundKey(state,round);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state,10);

        for(int i=0;i<16;i++){
            output[i]=(byte) state[i];
        }

    }




    private void addRoundKey(int[] state, int round) {
        int roundKeyStart=round*16;

        for(int i=0;i<16;i++){
            state[i]= byteOp.combine(state[i],roundKeys[roundKeyStart + i]);
        }
    }

    private void subBytes(int[] state) {
        for(int i=0;i<16;i++){
            state[i]=Table.SBOX[state[i]];
        }
    }

    private void shiftRows(int[] state) {
        int[] shifted=new int[16];

        for(int row=0;row<4;row++){
            for(int col=0;col<4;col++){
                int sourceCol=(col + row)%4;
                shifted[row + 4*col]=state[row+4*sourceCol];
            }
        }
        System.arraycopy(shifted,0,state,0,16);
    }

    private void mixCoulmns(int[] state) {
        for(int col=0;col<4;col++){
            int i=4*col;

            int a0=state[i];
            int a1=state[i+1];
            int a2=state[i+2];
            int a3=state[i+3];
            state[i]     = byteOp.combine(
                    byteOp.combine(gf.mul(a0, 2), gf.mul(a1, 3)),
                    byteOp.combine(a2, a3));

            state[i + 1] = byteOp.combine(
                    byteOp.combine(a0, gf.mul(a1, 2)),
                    byteOp.combine(gf.mul(a2, 3), a3));

            state[i + 2] = byteOp.combine(
                    byteOp.combine(a0, a1),
                    byteOp.combine(gf.mul(a2, 2), gf.mul(a3, 3)));

            state[i + 3] = byteOp.combine(
                    byteOp.combine(gf.mul(a0, 3), a1),
                    byteOp.combine(a2, gf.mul(a3, 2)));
        }
    }

    private void invShiftRows(int[] state) {
        int[] shifted = new int[16];

        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                int sourceCol = (col - row + 4) % 4;
                shifted[row + 4 * col] = state[row + 4 * sourceCol];
            }
        }

        System.arraycopy(shifted, 0, state, 0, 16);
    }

    private void invSubBytes(int[] state) {
        for(int i=0;i<16;i++){
            state[i]=Table.INV_SBOX[state[i]];
        }
    }

    private void invMixColumns(int[] state) {
        for (int col = 0; col < 4; col++) {
            int i = 4 * col;

            int a0 = state[i];
            int a1 = state[i + 1];
            int a2 = state[i + 2];
            int a3 = state[i + 3];

            state[i] = combineProducts(
                    gf.mul(a0, 14), gf.mul(a1, 11),
                    gf.mul(a2, 13), gf.mul(a3, 9));

            state[i + 1] = combineProducts(
                    gf.mul(a0, 9), gf.mul(a1, 14),
                    gf.mul(a2, 11), gf.mul(a3, 13));

            state[i + 2] = combineProducts(
                    gf.mul(a0, 13), gf.mul(a1, 9),
                    gf.mul(a2, 14), gf.mul(a3, 11));

            state[i + 3] = combineProducts(
                    gf.mul(a0, 11), gf.mul(a1, 13),
                    gf.mul(a2, 9), gf.mul(a3, 14));
        }
    }

    private int combineProducts(int a, int b, int c, int d) {
        return byteOp.combine(
                byteOp.combine(a, b),
                byteOp.combine(c, d));
    }

    public void decryptBlock(byte[] input, byte[] output) {
        if (input.length != 16 || output.length != 16) {
            throw new IllegalArgumentException(
                    "AES decrypts exactly one 16-byte block");
        }

        int[] state = new int[16];
        for (int i = 0; i < 16; i++) {
            state[i] = input[i] & 0xFF;
        }

        addRoundKey(state, 10);

        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        for (int i = 0; i < 16; i++) {
            output[i] = (byte) state[i];
        }
    }

}
