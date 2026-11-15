package org.XorAES;

public class ArithXorOp implements ByteOp{
    @Override
    public int combine(int a, int b) {
        return ((a + b - 2 * (a & b)) & 0xFF);
    }

    @Override
    public String name() {
        return "Arithmetic identity";
    }
}
