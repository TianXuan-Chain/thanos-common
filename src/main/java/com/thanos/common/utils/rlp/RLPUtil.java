package com.thanos.common.utils.rlp;

import com.thanos.common.utils.ByteArrayWrapper;
import com.thanos.common.utils.ByteUtil;

import java.util.HashSet;
import java.util.Set;

/**
 * 类RLPUtil.java的实现描述：
 *
 * @Author laiyiyu create on 2020-01-20 16:23:42
 */
public class RLPUtil {
    public static byte[] rlpEncodeLong(long n) {
        // TODO for now leaving int cast
        return RLP.encodeInt((int) n);
    }

    public static byte rlpDecodeByte(RLPElement elem) {
        return (byte) rlpDecodeInt(elem);
    }

    public static long rlpDecodeLong(RLPElement elem) {
        return rlpDecodeInt(elem);
    }

    public static int rlpDecodeInt(RLPElement elem) {
        byte[] b = elem.getRLPData();
        if (b == null) return 0;
        return ByteUtil.byteArrayToInt(b);
    }

    public static String rlpDecodeString(RLPElement elem) {
        byte[] b = elem.getRLPData();
        if (b == null) return null;
        return new String(b);
    }

    public static Set<ByteArrayWrapper> rlpDecodeSet(RLPElement elem) {
        byte[] setEncoded = elem.getRLPData();
        RLPList list = (RLPList) RLP.decode2(setEncoded).get(0);
        Set<ByteArrayWrapper> result = new HashSet<>(list.size());
        for (RLPElement byteArr: list) {
            result.add(new ByteArrayWrapper(byteArr.getRLPData()));
        }
        return result;
    }

    public static byte[] rlpEncodeList(Object ... elems) {
        byte[][] encodedElems = new byte[elems.length][];
        for (int i =0; i < elems.length; i++) {
            if (elems[i] instanceof Byte) {
                encodedElems[i] = RLP.encodeByte((Byte) elems[i]);
            } else if (elems[i] instanceof Integer) {
                encodedElems[i] = RLP.encodeInt((Integer) elems[i]);
            } else if (elems[i] instanceof Long) {
                encodedElems[i] = rlpEncodeLong((Long) elems[i]);
            } else if (elems[i] instanceof String) {
                encodedElems[i] = RLP.encodeString((String) elems[i]);
            } else if (elems[i] instanceof byte[]) {
                encodedElems[i] = ((byte[]) elems[i]);
            } else {
                throw new RuntimeException("Unsupported object: " + elems[i]);
            }
        }
        return RLP.encodeList(encodedElems);
    }

}
