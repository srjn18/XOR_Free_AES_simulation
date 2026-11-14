package org.XorAES;

public final class KeyExpansion {
    private final ByteOp byteOp;

    public KeyExpansion(ByteOp byteOp) {
        this.byteOp = byteOp;
    }

    public int[] expand(byte[] key16){
        if(key16.length!=16){
            throw new IllegalArgumentException("AES-128 key must be 16 bytes");
        }

        int[] expanded = new int[176];

        for(int i=0;i<16;i++){
            expanded[i]=key16[i]&0xFF;
        }

        int bytesGenerated=16;
        int rconIndex=0;
        int[] temp=new int[4];

        while(bytesGenerated< expanded.length){
            //substitution
            for(int i=0;i<4;i++){
                temp[i]=expanded[bytesGenerated-4+i];
                rconIndex++;
            }
            if(bytesGenerated %16==0){
                int first=temp[0];
                temp[0]=temp[1];
                temp[1]=temp[2];
                temp[2]=temp[3];
                temp[3]=first;

                for(int i=0;i<4;i++){
                    temp[i]=Table.SBOX[temp[i]];
                }

                for(int i=0;i<4;i++){
                    byteOp.combine(expanded[bytesGenerated-16], temp[i]);
                    bytesGenerated++;
                }
            }
        }
        return expanded;
    }
}
