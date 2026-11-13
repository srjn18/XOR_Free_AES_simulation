package org.XorAES;

public class NativeXorOp implements ByteOp{
    @Override
    public int combine(int a, int b) {
        return (a^b) & 0xFF;
    }

    @Override
    public String name() {
        return "Native Xor";
    }
}
