package com.thanos.common.utils;


import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.math.BigInteger;

/**
 * 类StdDERUtil.java的实现描述：DER工具类
 *
 * @author xuhao create on 2021/4/20 20:43
 */

public class StdDSAEncoder {

    public static byte[] encode(
            BigInteger r,
            BigInteger s)
            throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));

        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public static BigInteger[] decode(
            byte[] encoding)
            throws IOException {
        ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
        BigInteger[] sig = new BigInteger[2];

        sig[0] = ((ASN1Integer) s.getObjectAt(0)).getValue();
        sig[1] = ((ASN1Integer) s.getObjectAt(1)).getValue();

        return sig;
    }
}
