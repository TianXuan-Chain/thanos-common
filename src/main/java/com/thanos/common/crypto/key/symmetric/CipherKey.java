package com.thanos.common.crypto.key.symmetric;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 类CipherKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/25 17:23
 */

public abstract class CipherKey {
    protected static final Logger logger = LoggerFactory.getLogger("crypto");

    public static CipherKey fromKeyBytes(byte[] keyBytes, String keyTypeDesc) {
        CipherKeyType keyType = CipherKeyType.getKeyTypeByDescription(keyTypeDesc);
        if (keyType == null) {
            logger.error("CipherKey getInstance error, algorithm [" + keyTypeDesc + "] not supported.");
            throw new RuntimeException("CipherKey getInstance error, algorithm [" + keyTypeDesc + "] not supported.");
        }

        switch (keyType) {
            case AES:
                return AESKey.fromKeyBytes(keyBytes);
            case SM4:
                return SM4Key.fromKeyBytes(keyBytes);
            default:
                return new DefaultCipherKey();
        }
    }

    //
    public static CipherKey getInstance(String keyTypeDesc) {
        CipherKeyType keyType = CipherKeyType.getKeyTypeByDescription(keyTypeDesc);
        if (keyType == null) {
            logger.error("CipherKey getInstance error, algorithm [" + keyTypeDesc + "] not supported.");
            throw new RuntimeException("CipherKey getInstance error, algorithm [" + keyTypeDesc + "] not supported.");
        }
        switch (keyType) {
            case AES:
                return new AESKey();
            case SM4:
                return new SM4Key();
            default:
                return new DefaultCipherKey();
        }
    }

    public abstract byte[] encrypt(byte[] data);

    public abstract byte[] decrypt(byte[] data);

    public abstract byte[] getKeyBytes();
}
