package com.thanos.common.crypto.key.asymmetric.ntru;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.asymmetric.SecureKeyType;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import net.sf.ntru.sign.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * NTRUKey.java description：
 *
 * @Author lemon819 create on 2020-11-20 10:04:07
 */
public class NTRUKey extends SecureKey {
    public static final String ALGORITHM = "NTRU";

    private final SignatureKeyPair keyPair;
    // private final SignaturePrivateKey privateKey;

    public NTRUKey(short shardingNumber) {
        final NtruSign sign = new NtruSign(SignatureParameters.APR2011_439_PROD);
        SignatureKeyPair keyPair = sign.generateKeyPair();
        this.keyPair = keyPair;
        //  this.privateKey = keyPair.getPrivate();
        final SignaturePublicKey signaturePublicKey = keyPair.getPublic();
        this.securePublicKey = SecurePublicKey.generate(signaturePublicKey.getEncoded(), SecureKeyType.PQC.getCode(), shardingNumber);

//        {
//            byte[] keyPairBytes = keyPair.getEncoded();
//           // byte[] privateKeyBytes = privateKey.getEncoded();
//            byte[] securePublicKeyBytes = securePublicKey.getPubKey();
//            byte[] test ="test".getBytes();
//            System.out.println("keyPairBytes: " + Hex.toHexString(keyPairBytes));
//            System.out.println("securePublicKeyBytes: " + Hex.toHexString(securePublicKeyBytes));
//        }
    }

    public NTRUKey(SignatureKeyPair keyPair, short shardingNumber) {
        this.keyPair = keyPair;
        // this.privateKey = keyPair.getPrivate();
        this.securePublicKey = SecurePublicKey.generate(keyPair.getPublic().getEncoded(), SecureKeyType.PQC.getCode(), shardingNumber);

//        {
//            byte[] keyPair1Bytes = keyPair.getEncoded();
//           // byte[] privateKey1Bytes = privateKey.getEncoded();
//            byte[] securePublicKey1Bytes = securePublicKey.getPubKey();
//            byte[] test1 = "test1".getBytes();
//            System.out.println("keyPair1Bytes: " + Hex.toHexString(keyPair1Bytes));
//            System.out.println("securePublicKey1Bytes: " + Hex.toHexString(securePublicKey1Bytes));
//        }
    }

    public static NTRUKey fromPrivate(byte[] privKeyBytes, short shardingNumber) {
        return new NTRUKey(keyPairFromBytes(privKeyBytes), shardingNumber);
    }

    private static SignatureKeyPair keyPairFromBytes(byte[] keypairBytes) {
        return new SignatureKeyPair(keypairBytes);
    }

    protected byte[] doGetPrivKeyBytes() {
        if (keyPair == null) {
            return null;
        }
        return keyPair.getEncoded();
    }

    public byte[] sign(byte[] messageHash) {
        if (keyPair == null)
            throw new MissingPrivateKeyException();
        NtruSign sign = new NtruSign(SignatureParameters.APR2011_439_PROD);
        sign.initSign(keyPair);
        return sign.sign(messageHash);
    }


    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("pub:").append(Hex.toHexString(this.securePublicKey.getPubKey()));
        return b.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NTRUKey)) return false;

        NTRUKey ntruKey = (NTRUKey) o;
        return Arrays.areEqual(this.doGetPrivKeyBytes(),ntruKey.doGetPrivKeyBytes());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.securePublicKey.getPubKey());
    }

    public static void main(String[] args) {
        SecureKey NTRUKey = SecureKey.getInstance("PQC", 1);
        System.out.println("privKey:" + Hex.toHexString(NTRUKey.getPrivKeyBytes()));
        System.out.println("pubkey:" + Hex.toHexString(NTRUKey.getPubKey()));
        System.out.println("nodeId:" + Hex.toHexString(NTRUKey.getNodeId()));
    }
}
