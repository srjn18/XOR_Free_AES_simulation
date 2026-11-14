package org.XorAES;

public class GF256 {
    private final ByteOp byteOp;

    public GF256(ByteOp byteOp){
        if(byteOp==null) {
            throw new IllegalArgumentException("byte Operation cannot be null");
        }
        this.byteOp=byteOp;
    }

    /*
    to multiply we use combine() method
     */
    public int xtime(int a) {
        a &= 0xFF;
        int shifted = (a << 1) & 0xFF;
        if ((a & 0xFF) != 0)
            shifted = byteOp.combine(shifted, 0x1B);

        return shifted;
    }

    public int mul(int a,int b){
        a &= 0xFF;
        b &= 0xFF;

        int result=0;
        int current=a;

        for(int bit=0;bit<8;bit++) {
            if ((b & 1) != 0)
                result = byteOp.combine(result, current);
            current = xtime(current);
            b >>>= 1;
        }
        return result & 0xFF;
    }
}
