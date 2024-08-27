package com.thanos.common.crypto.key.asymmetric.sm;


import com.thanos.common.crypto.CastleProvider;
import com.thanos.common.crypto.jce.SMKeyPairGenerator;
import com.thanos.common.crypto.key.asymmetric.SecureKeyType;
import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.HashUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import static com.thanos.common.utils.ByteUtil.bigIntegerToBytes;
import static com.thanos.common.utils.ByteUtil.toHexString;

/**
 * 类SMKey.java的实现描述：国密密钥类
 *
 * @author xuhao create on 2020/11/11 11:23
 */


public class SMKey extends SecureKey {

    /**
     * The parameters of the sm2p256v1 curve.
     */
    public static final ECDomainParameters CURVE;

    public static final ECParameterSpec CURVE_SPEC;

    public static final String SM2_WITH_SM3 = GMObjectIdentifiers.sm2sign_with_sm3.toString();

    public static final String ALGORITHM = "EC";


    private static final SecureRandom secureRandom;

    static {
        X9ECParameters params = GMNamedCurves.getByName("sm2p256v1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
        secureRandom = new SecureRandom();
    }

    private final PrivateKey privKey;

    public SMKey(short shardingNumber) {
        this(secureRandom, shardingNumber);
    }

    /**
     * Generates an entirely new keypair with the given {@link SecureRandom} object.
     * <p>
     * BouncyCastle will be used as the Java Security Provider
     *
     * @param secureRandom -
     */
    public SMKey(SecureRandom secureRandom, short shardingNumber) {
        this(CastleProvider.getBouncyInstance(), secureRandom, shardingNumber);
    }


    /**
     * Generate a new keypair using the given Java Security Provider.
     * <p>
     * All private key operations will use the provider.
     */
    public SMKey(Provider provider, SecureRandom secureRandom, short shardingNumber) {

        final KeyPairGenerator keyPairGen = SMKeyPairGenerator.getInstance(provider, secureRandom);
        final KeyPair keyPair = keyPairGen.generateKeyPair();

        this.privKey = keyPair.getPrivate();

        final PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof BCECPublicKey) {
            byte[] pubBytes = ((BCECPublicKey) pubKey).getQ().getEncoded(false);
            this.securePublicKey = SecurePublicKey.generate(pubBytes, SecureKeyType.SM.getCode(), shardingNumber);
        } else {
            throw new AssertionError(
                    "Expected Provider " + provider.getName() +
                            " to produce a subtype of SM PublicKey, found " + pubKey.getClass());
        }
    }


    public SMKey(PrivateKey privKey, short shardingNumber) {
        if (privKey instanceof BCECPrivateKey) {
            this.privKey = privKey;
            BigInteger d = ((BCECPrivateKey) privKey).getD();
            byte[] pubBytes = CURVE.getG().multiply(d).getEncoded(false);
            this.securePublicKey = SecurePublicKey.generate(pubBytes, SecureKeyType.SM.getCode(), shardingNumber);
        } else {
            throw new IllegalArgumentException(
                    "Expected SM private key, given a private key object with class " +
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
    public static SMKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return new SMKey(privateKeyFromBytes(privKeyBytes), shardingNumber);
    }


    protected byte[] doGetPrivKeyBytes() {
        if (privKey == null) {
            return null;
        } else if (privKey instanceof BCECPrivateKey) {
            return bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32);
        } else {
            return null;
        }
    }


    public byte[] sign(byte[] messageHash) {
        // No decryption of private key required.
        if (privKey == null)
            throw new MissingPrivateKeyException();
        try {
            Signature signature = Signature.getInstance(SM2_WITH_SM3, "BC");
            signature.initSign(privKey);
            signature.update(messageHash);
            return signature.sign();
        } catch (InvalidKeyException e) {
            logger.error("SMKey sign  failed, msgHash:{}.", Hex.toHexString(messageHash), e);
            throw new AssertionError("Assumed correct sm privKey ", e);
        } catch (Exception e) {
            logger.error("SMKey sign  failed, msgHash:{}.", Hex.toHexString(messageHash), e);
            throw new AssertionError("SMKey sign failed.", e);
        }
    }



    /* Convert a byte slice into a PrivateKey object
     */
    private static PrivateKey privateKeyFromBytes(byte[] privKeyBytes) {
        if (privKeyBytes == null) {
            return null;
        } else {
            try {
                BigInteger d = new BigInteger(1, privKeyBytes);
                return KeyFactory.getInstance(ALGORITHM, CastleProvider.getBouncyInstance())
                        .generatePrivate(new ECPrivateKeySpec(d, CURVE_SPEC));
            } catch (InvalidKeySpecException ex) {
                throw new AssertionError("Assumed correct SM2 key spec statically", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new AssertionError("Assumed correct algorithm of SM2 privKey", ex);
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("pub:").append(toHexString(this.securePublicKey.getPubKey()));
        return b.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SMKey)) return false;

        SMKey smKey = (SMKey) o;
        return privKey.equals(smKey.privKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.securePublicKey.getPubKey());
    }

    public static void main(String[] args) {
//        Security.addProvider(SpongyCastleProvider.getInstance());
//        Security.addProvider(BouncyCastleProviderFactory.getInstance());
        SMKey smKey = new SMKey((short) 1);
        System.out.println(Hex.toHexString(smKey.doGetPrivKeyBytes()));
        byte[] privKeyBytes = Hex.decode("a38f1c2ac8e2982c1232c6c138ce582cdc9f06e1fdf15d6507a7000d24dfd821");
////        byte[] privKeyBytes = Hex.decode("302e020100300506032b65700422042068406ea328404e0bebfb911c281064fbcde38ff8edd7bc660b34ac5ca3746e62");
        SMKey key = SMKey.fromPrivate(privKeyBytes, (short) 1);
        System.out.println("key.privKey: " + Hex.toHexString(key.doGetPrivKeyBytes()));
        System.out.println("key.pubKey: " + Hex.toHexString(key.securePublicKey.getPubKey()));
//
        byte[] pubKeyBytes = Hex.decode("04280ae01ca8134c15bbd40a5e81045a09b59373a85b6263fac9461986fb2fbe30b9462bf76e4be56caafb000f086e4acc6833eaded991bb9bdfc479e53e3193f9");
        SecurePublicKey key2 = SecurePublicKey.generate(pubKeyBytes);
        System.out.println("key2.pubKey: " + Hex.toHexString(key2.getPubKey()));
//
        byte[] msg = HashUtil.sha3("Hello world".getBytes());
        byte[] sig = key.sign(msg);
        System.out.println("sig: " + Hex.toHexString(sig));
        System.out.println(key2.verify(msg, sig));

    }
}
