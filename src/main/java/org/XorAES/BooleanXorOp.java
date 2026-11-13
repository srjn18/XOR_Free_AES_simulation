package org.XorAES;

public class BooleanXorOp implements ByteOp{
    @Override
    public int combine(int a, int b) {
        return ((a | b) & ~(a & b)) & 0xFF;
    }

    @Override
    public String name() {
        return "Boolean identity";
    }
}
