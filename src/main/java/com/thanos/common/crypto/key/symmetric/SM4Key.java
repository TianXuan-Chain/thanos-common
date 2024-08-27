package com.thanos.common.crypto.key.symmetric;

import com.thanos.common.crypto.CastleProvider;
import org.spongycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * 类SM4Key.java的实现描述：
 *
 * @author xuhao create on 2020/11/25 17:35
 */

public class SM4Key extends CipherKey {
    //算法名
    public static final String KEY_ALGORITHM = "SM4";
    public static final String CIPHER_ALGORITHM = "SM4/CBC/PKCS5Padding";
    public final int blockSize;
    private final IvParameterSpec ivSpec;

    private SecretKey key;

    public SM4Key() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, CastleProvider.getBouncyInstance().getName());
            keyGenerator.init(128);
            key = keyGenerator.generateKey();
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            blockSize = cipher.getBlockSize();
            byte[] initVector = new byte[blockSize];
            ivSpec = new IvParameterSpec(initVector);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SM4Key generate failed, algorithm[" + KEY_ALGORITHM + "] not supported.");
        } catch (Exception e) {
            throw new RuntimeException("SM4Key generate failed. ", e);
        }
    }

    public SM4Key(SecretKey key) {
        try {
            this.key = key;
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            blockSize = cipher.getBlockSize();
            byte[] initVector = new byte[blockSize];
            ivSpec = new IvParameterSpec(initVector);
        } catch (Exception e) {
            throw new RuntimeException("SM4Key generate failed. ", e);
        }
    }


    public static SM4Key fromKeyBytes(byte[] keyBytes) {
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        return new SM4Key(secretKey);
    }

    @Override
    public byte[] encrypt(byte[] data) {

        if (data == null) {
            return null;
        }

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            logger.error("SMKey encrypt error!", e);
            return data;
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try {
            if (data == null) {
                return null;
            }
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            logger.error("SMKey decrypt error!", e);
            return data;
        }
    }

    @Override
    public byte[] getKeyBytes() {
        return key.getEncoded();
    }

    public static void main(String[] args) {
        String sm4Key = "c9ec17b81d5abf18b979693faacbf917";
        CipherKey key1 = CipherKey.fromKeyBytes(Hex.decode(sm4Key), "SM4");
        byte[] data = "hello,world".getBytes();
        byte[] cipherText1 = key1.encrypt(data);
        System.out.println("cipherText1:" + Hex.toHexString(cipherText1));
        System.out.println("plainText1:" + Hex.toHexString(key1.decrypt(cipherText1)));
        CipherKey key2 = CipherKey.fromKeyBytes(Hex.decode(sm4Key), "SM4");
        byte[] cipherText2 = key2.encrypt(data);
        System.out.println("cipherText2:" + Hex.toHexString(cipherText2));
        System.out.println("plainText2:" + Hex.toHexString(key2.decrypt(cipherText2)));
    }
}
