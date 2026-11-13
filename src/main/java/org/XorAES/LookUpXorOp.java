package org.XorAES;

public class LookUpXorOp implements ByteOp{
    private static final int TABLE_SIZE=256*256;
    private final byte[] table=new byte[TABLE_SIZE];

    public LookUpXorOp(){
        for(int a=0;a<256;a++){
            for(int b=0;b<256;b++){
                int index=(a<<8)|b;
                table[index]=(byte)((a+b-2*(a|b)) & 0xFF);

            }
        }
    }
    @Override
    public int combine(int a, int b) {
        int index=((a<<8)& 0xFF) | (b &0xFF);
        return table[index] & 0xFF;
    }

    @Override
    public String name() {
        return "Lookup Table";
    }
}
