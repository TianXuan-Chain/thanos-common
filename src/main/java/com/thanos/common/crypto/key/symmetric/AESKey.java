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
 * 类AESKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/25 17:35
 */

public class AESKey extends CipherKey {
    //算法名
    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public final int blockSize;
    private final IvParameterSpec ivSpec;

    private SecretKey key;

    public AESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(128);
            key = keyGenerator.generateKey();
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            blockSize = cipher.getBlockSize();
            byte[] initVector = new byte[blockSize];
            ivSpec = new IvParameterSpec(initVector);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AESKey generate failed, algorithm[" + KEY_ALGORITHM + "] not supported.");
        } catch (Exception e) {
            throw new RuntimeException("AESKey generate failed. ", e);
        }
    }

    public AESKey(SecretKey key) {
        try {
            this.key = key;
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            blockSize = cipher.getBlockSize();
            byte[] initVector = new byte[blockSize];
            ivSpec = new IvParameterSpec(initVector);
        } catch (Exception e) {
            throw new RuntimeException("AESKey generate failed. ", e);
        }
    }


    public static AESKey fromKeyBytes(byte[] keyBytes) {
        SecretKey secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        return new AESKey(secretKey);
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
            logger.error("AESKey encrypt error!", e);
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
            logger.error("AESKey decrypt error!", e);
            return data;
        }
    }

    @Override
    public byte[] getKeyBytes() {
        return key.getEncoded();
    }

    public static void main(String[] args) {
        String aesKey = "c9ec17b81d5abf18b979693faacbf917";
        CipherKey key1 = CipherKey.fromKeyBytes(Hex.decode(aesKey), "AES");
        System.out.println("key1: " + Hex.toHexString(key1.getKeyBytes()));
        byte[] data = "hello,world".getBytes();
        byte[] cipherText1 = key1.encrypt(data);
        System.out.println("cipherText1:" + Hex.toHexString(cipherText1));
        System.out.println("plainText1:" + Hex.toHexString(key1.decrypt(cipherText1)));
        CipherKey key2 = CipherKey.fromKeyBytes(Hex.decode(aesKey), "AES");
        byte[] cipherText2 = key2.encrypt(data);
        System.out.println("cipherText2:" + Hex.toHexString(cipherText2));
        System.out.println("plainText2:" + Hex.toHexString(key2.decrypt(cipherText2)));
    }
}
