package com.thanos.common.crypto.key.asymmetric;


import com.thanos.common.crypto.key.asymmetric.ec.ECPublicKey;
import com.thanos.common.crypto.key.asymmetric.ed.EDPublicKey;
import com.thanos.common.crypto.key.asymmetric.ntru.NTRUPublicKey;
import com.thanos.common.crypto.key.asymmetric.sm.SMPublicKey;
import com.thanos.common.utils.ByteUtil;
import com.thanos.common.utils.HashUtil;
import net.sf.ntru.sign.SignaturePublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * 类SecureKey.java的实现描述：密钥抽象类
 *
 * @author xuhao create on 2020/9/8 14:34
 */

public abstract class SecurePublicKey {

    protected static final Logger logger = LoggerFactory.getLogger("crypto");

    //公钥的第1个字节是算法类型
    private int type;

    //公钥的第2~3个字节是节点所属shardingNumber.
    private short shardingNumber;

    protected PublicKey publicKey;

    protected SignaturePublicKey signaturePublicKey;
    //公钥字符串不带前缀
    protected byte[] pub;
    //公钥字符串带前缀【算法类型+节点所属分片号】
    protected byte[] pubWithPrefix;
    //区块链地址
    protected byte[] address;
    //节点id 64字节
    protected byte[] nodeId;

    public static SecurePublicKey generate(byte[] publicKeyBytes, int typeCode, short shardingNumber) {
        SecureKeyType keyType = SecureKeyType.getKeyTypeByCode(typeCode);
        if (keyType == null) {
            String errInfo = String.format("SecurePublicKey generate failed，SignAlgorithm with code[%d] not supported.", typeCode);
            logger.error(errInfo);
            throw new RuntimeException(errInfo);
        }
        SecurePublicKey securePublicKey;
        switch (keyType) {
            case ECDSA:
                securePublicKey = new ECPublicKey(Arrays.copyOfRange(publicKeyBytes, 0, publicKeyBytes.length));
                break;
            case ED25519:
                securePublicKey = new EDPublicKey(Arrays.copyOfRange(publicKeyBytes, 0, publicKeyBytes.length));
                break;
            case SM:
                securePublicKey = new SMPublicKey(Arrays.copyOfRange(publicKeyBytes, 0, publicKeyBytes.length));
                break;
            case PQC:
                securePublicKey = new NTRUPublicKey(Arrays.copyOfRange(publicKeyBytes, 0, publicKeyBytes.length));
                break;
            default:
                String errInfo = String.format("SecureKey verify failed，unknown keyType:[%s]", keyType);
                logger.error(errInfo);
                throw new RuntimeException(errInfo);
        }
        securePublicKey.type = typeCode;
        securePublicKey.shardingNumber = shardingNumber;
        securePublicKey.pubWithPrefix = securePublicKey.withKeyPrefix(publicKeyBytes);
        return securePublicKey;
    }

    public static SecurePublicKey generate(byte[] publicKeyRawBytes) {
        int typeCode = ByteUtil.byteArrayToInt(Arrays.copyOfRange(publicKeyRawBytes, 0, 1));
        short shardingNumber = ByteUtil.byteArrayToShort(Arrays.copyOfRange(publicKeyRawBytes, 1, 3));
        return generate(Arrays.copyOfRange(publicKeyRawBytes, 3, publicKeyRawBytes.length), typeCode, shardingNumber);
    }

    public abstract byte[] getNodeId();


    public byte[] getAddress() {
        if (address == null) {
            address = computeAddress(this.pub);
        }
        return address;
    }

    public abstract byte[] computeAddress(byte[] pubBytes);


    public int getShardingNumber() {
        return shardingNumber;
    }

    public int getType() {
        return type;
    }


    public byte[] getPubKey() {
        return ByteUtil.copyFrom(this.pubWithPrefix);
    }

    public abstract boolean verify(byte[] data, byte[] sig);


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

}
