package org.XorAES;

public interface ByteOp {
    /*
    combine() method is used to take 2 byte values and return a byte value
    int is the return type as its byte takes signed values and we want only +ve(unsigned values)

    name() method is only as a label for verification
     */
    int combine(int a,int b);

    String name();
}
