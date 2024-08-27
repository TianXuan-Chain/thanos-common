package com.thanos.common.crypto.key.asymmetric.ed;

import com.thanos.common.crypto.CastleProvider;
import com.thanos.common.crypto.jce.EDKeyPairGenerator;
import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.SecureKeyType;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import static com.thanos.common.utils.ByteUtil.toHexString;

/**
 * 类EDKey.java的实现描述：
 *
 * @author xuhao create on 2020/9/8 15:31
 */

public class EDKey extends SecureKey {

    private static final String ED25519_PRIVATE_KEY_PREFIX = "302e020100300506032b657004220420";//使用openssl命令行产生的ed25519私钥前缀

    private static final String ED25519_DEFAULT_PRIVATE_KEY_PREFIX = "3051020101300506032b657004220420";//使用默认构造方法产生的ed25519私钥前缀

    public static final String ALGORITHM = "EdDSA";

    public static final String ED25519 = "Ed25519";

    private static final SecureRandom secureRandom;

    static {
        secureRandom = new SecureRandom();
    }

    private final PrivateKey privKey;


    public EDKey(short shardingNumber) {
        this(secureRandom, shardingNumber);
    }

    /**
     * Generates an entirely new keypair with the given {@link SecureRandom} object.
     * <p>
     * BouncyCastle will be used as the Java Security Provider
     *
     * @param secureRandom -
     */
    public EDKey(SecureRandom secureRandom, short shardingNumber) {
        this(CastleProvider.getBouncyInstance(), secureRandom, shardingNumber);
    }


    /**
     * Generate a new keypair using the given Java Security Provider.
     * <p>
     * All private key operations will use the provider.
     */
    public EDKey(Provider provider, SecureRandom secureRandom, short shardingNumber) {

        final KeyPairGenerator keyPairGen = EDKeyPairGenerator.getInstance(provider, secureRandom);
        final KeyPair keyPair = keyPairGen.generateKeyPair();

        this.privKey = keyPair.getPrivate();

        final PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof BCEdDSAPublicKey) {
            this.securePublicKey = SecurePublicKey.generate(pubKey.getEncoded(), SecureKeyType.ED25519.getCode(), shardingNumber);
        } else {
            throw new AssertionError(
                    "Expected Provider " + provider.getName() +
                            " to produce a subtype of EdDSAPublicKey, found " + pubKey.getClass());
        }
    }

    public EDKey(PrivateKey privKey, short shardingNumber) {

        if (privKey instanceof EdDSAPrivateKey) {
            this.privKey = privKey;
            byte[] pubBytes = ((EdDSAPrivateKey) privKey).getPublicKey().getEncoded();
            this.securePublicKey = SecurePublicKey.generate(pubBytes, SecureKeyType.ED25519.getCode(), shardingNumber);
        } else {
            throw new IllegalArgumentException(
                    "Expected ED private key, given a private key object with class " +
                            privKey.getClass().toString() +
                            " and algorithm " + privKey.getAlgorithm());
        }
    }

    /**
     * Creates an ECKey given the private key only.
     *
     * @param privKeyBytes -
     * @return -
     */
    public static EDKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return new EDKey(privateKeyFromBytes(formatPrivate(privKeyBytes)), shardingNumber);
    }


    protected byte[] doGetPrivKeyBytes() {
        if (privKey == null) {
            return null;
        }
        return privKey.getEncoded();
    }


    public byte[] sign(byte[] messageHash) {
        // No decryption of private key required.
        if (privKey == null)
            throw new MissingPrivateKeyException();
        try {
            Signature signature = Signature.getInstance(ED25519, "BC");
            signature.initSign(privKey);
            signature.update(messageHash);
            return signature.sign();
        } catch (InvalidKeyException e) {
            logger.error("EDKey sign  failed, msgHash:{}.", Hex.toHexString(messageHash), e);
            throw new AssertionError("Assumed correct ed25519 privKey ", e);
        } catch (Exception e) {
            logger.error("EDKey sign  failed, msgHash:{}.", Hex.toHexString(messageHash), e);
            throw new AssertionError("EDKey sign failed.", e);
        }
    }



    //私钥标准化，统一加上Ed25519PrivKeyPrefix前缀
    private static byte[] formatPrivate(byte[] privKeyBytes) {
        if (privKeyBytes == null) {
            return null;
        }
        String privKeyStr = Hex.toHexString(privKeyBytes);
        if (privKeyStr.startsWith(ED25519_DEFAULT_PRIVATE_KEY_PREFIX)) {
            return Hex.decode(privKeyStr);
        }
        if (!privKeyStr.startsWith(ED25519_PRIVATE_KEY_PREFIX)) {
            privKeyStr = ED25519_PRIVATE_KEY_PREFIX + privKeyStr;
        }
        return Hex.decode(privKeyStr);
    }


    /* Convert a byte slice into a PrivateKey object
     */
    private static PrivateKey privateKeyFromBytes(byte[] privKeyBytes) {
        if (privKeyBytes == null) {
            return null;
        } else {
            try {
                return KeyFactory.getInstance(ALGORITHM, CastleProvider.getBouncyInstance())
                        .generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));
            } catch (InvalidKeySpecException ex) {
                throw new AssertionError("Assumed correct EdDSA key spec statically", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new AssertionError("Assumed correct algorithm of EdDSA privKey", ex);
            }
        }
    }


    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("pub:").append(toHexString(this.securePublicKey.getPubKey()));
        return b.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EDKey)) return false;

        EDKey edKey = (EDKey) o;
        return privKey.equals(edKey.privKey);

    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.securePublicKey.getPubKey());
    }


    public static void main(String[] args) {
//        Security.addProvider(SpongyCastleProvider.getInstance());
//        Security.addProvider(BouncyCastleProviderFactory.getInstance());
        SecureKey edKey = SecureKey.getInstance("ED25519", 1);
        System.out.println(Hex.toHexString(edKey.getPrivKeyBytes()));

    }
}
