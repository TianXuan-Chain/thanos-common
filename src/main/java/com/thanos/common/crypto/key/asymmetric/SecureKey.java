package com.thanos.common.crypto.key.asymmetric;


import com.thanos.common.crypto.key.asymmetric.factory.*;
import com.thanos.common.utils.ByteUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

/**
 * 类SecureKey.java的实现描述：密钥抽象类
 *
 * @author xuhao create on 2020/9/8 14:34
 */

public abstract class SecureKey {

    protected static final Logger logger = LoggerFactory.getLogger("crypto");

    private static HashMap<SecureKeyType, SecureKeyFactory> keyType2KeyFactoryMap = new HashMap<>();

    //公钥/私钥的第1个字节是算法类型
    private int type;

    //公钥/私钥的第2~3个字节是节点所属shardingNumber.
    private short shardingNumber;

    //公钥，用于进行验签
    protected SecurePublicKey securePublicKey;

    //默认密钥前缀，采用ECDSA算法，shardingNumber=1
    public static byte[] DEFULT_KEY_PREFIX = ByteUtil.hexStringToBytes("0x010001");


    static {
        keyType2KeyFactoryMap.put(SecureKeyType.ECDSA, new ECDSAKeyFactory());
        keyType2KeyFactoryMap.put(SecureKeyType.ED25519, new EDKeyFactory());
        keyType2KeyFactoryMap.put(SecureKeyType.SM, new SMKeyFactory());
        keyType2KeyFactoryMap.put(SecureKeyType.PQC, new NTRUKeyFactory());

    }

    public static SecureKey fromPrivate(byte[] privKeyBytes) {
        int typeCode = ByteUtil.byteArrayToInt(Arrays.copyOfRange(privKeyBytes, 0, 1));
        SecureKeyType keyType = SecureKeyType.getKeyTypeByCode(typeCode);
        if (keyType == null) {
            throw new RuntimeException("SecureKey fromPrivate failed, SignAlgorithm with code [" + typeCode + "] not supported.");
        }
        short shardingNumber = ByteUtil.byteArrayToShort(Arrays.copyOfRange(privKeyBytes, 1, 3));
        SecureKey secureKey = keyType2KeyFactoryMap.get(keyType).fromPrivate(Arrays.copyOfRange(privKeyBytes, 3, privKeyBytes.length), shardingNumber);
        secureKey.type = typeCode;
        secureKey.shardingNumber = shardingNumber;
        return secureKey;
    }

    public static SecureKey getInstance(String keyTypeDesc, int shardingNumber) {
        SecureKeyType keyType = SecureKeyType.getKeyTypeByDescription(keyTypeDesc);
        if (keyType == null) {
            throw new RuntimeException("SecureKey getInstance error, SignAlgorithm [" + keyTypeDesc + "] not supported.");
        }
        SecureKey secureKey = keyType2KeyFactoryMap.get(keyType).getInstance((short) shardingNumber);
        secureKey.type = keyType.getCode();
        secureKey.shardingNumber = (short) shardingNumber;
        return secureKey;
    }

    public static SecureKey getInstance(String keyTypeDesc, int shardingNumber, SecureRandom secureRandom) {
        SecureKeyType keyType = SecureKeyType.getKeyTypeByDescription(keyTypeDesc);
        if (keyType == null) {
            throw new RuntimeException("SecureKey getInstance failed, SignAlgorithm [" + keyTypeDesc + "] not supported.");
        }
        SecureKey secureKey = keyType2KeyFactoryMap.get(keyType).getInstance(secureRandom, (short) shardingNumber);
        secureKey.type = keyType.getCode();
        secureKey.shardingNumber = (short) shardingNumber;
        return secureKey;
    }

    public byte[] getNodeId() {
        return securePublicKey.getNodeId();
    }

    public byte[] getAddress() {
        return securePublicKey.getAddress();
    }

    public byte[] getPubKey() {
        return securePublicKey.getPubKey();
    }

    public int getShardingNumber() {
        return shardingNumber;
    }

    public int getType() {
        return type;
    }

    public byte[] getPrivKeyBytes() {
        byte[] privKeySrc = doGetPrivKeyBytes();
        return withKeyPrefix(privKeySrc);
    }

    protected abstract byte[] doGetPrivKeyBytes();


    public abstract byte[] sign(byte[] messageHash);

    public boolean verify(byte[] data, byte[] signature) {
        return securePublicKey.verify(data, signature);
    }


    public static byte[] withDefaultKeyPrefix(byte[] keySrc) {
        if (keySrc == null) {
            return null;
        }
        byte[] keyBytes = new byte[keySrc.length + 3];
        System.arraycopy(DEFULT_KEY_PREFIX, 0, keyBytes, 0, DEFULT_KEY_PREFIX.length);

        System.arraycopy(keySrc, 0, keyBytes, 3, keySrc.length);
        return keyBytes;
    }

    /**
     * 给密钥添加前缀：第1字节：密钥类型，第2~3字节：所属分片号
     *
     * @param keySrc
     * @return
     */
    private byte[] withKeyPrefix(byte[] keySrc) {
        if (keySrc == null) {
            return null;
        }
        byte[] keyBytes = new byte[keySrc.length + 3];
        //第1字节：密钥类型
        keyBytes[0] = (byte) type;
        //第2~3字节：所属分片号
        byte[] shardingNumBytes = ByteBuffer.allocate(Short.BYTES).putShort(shardingNumber).array();
        System.arraycopy(shardingNumBytes, 0, keyBytes, 1, shardingNumBytes.length);

        System.arraycopy(keySrc, 0, keyBytes, 3, keySrc.length);
        return keyBytes;
    }


    @SuppressWarnings("serial")
    public static class MissingPrivateKeyException extends RuntimeException {
    }
}
