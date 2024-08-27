package com.thanos.common.crypto;

import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.ByteUtil;
import org.spongycastle.util.encoders.Hex;

import java.util.Arrays;

/**
 * VerifyingKey.java description：
 *
 * @Author laiyiyu create on 2020-03-08 17:56:57
 */
public class VerifyingKey {

    byte[] key;

    SecurePublicKey securePublicKey;

    public VerifyingKey(byte[] key) {
        this.key = key;
        this.securePublicKey = SecurePublicKey.generate(key);
    }

    public byte[] getKey() {
        return key;
    }

    public SecurePublicKey getSecurePublicKey() {
        return securePublicKey;
    }

    public VerifyingKey clone() {
        return new VerifyingKey(ByteUtil.copyFrom(this.key));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifyingKey that = (VerifyingKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

    @Override
    public String toString() {
        return "VerifyingKey{" +
                "key=" + Hex.toHexString(key) +
                '}';
    }
}
