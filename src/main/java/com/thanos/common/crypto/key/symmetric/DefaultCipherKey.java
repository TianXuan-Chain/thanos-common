package com.thanos.common.crypto.key.symmetric;

/**
 * 类DefaultCipherKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/26 11:40
 */

public class DefaultCipherKey extends CipherKey{

    @Override
    public byte[] encrypt(byte[] data) {
        return data;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return data;
    }

    @Override
    public byte[] getKeyBytes() {
        return null;
    }
}
