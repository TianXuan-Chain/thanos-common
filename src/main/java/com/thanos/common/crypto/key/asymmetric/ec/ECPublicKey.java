package com.thanos.common.crypto.key.asymmetric.ec;

import com.thanos.common.crypto.CastleProvider;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.HashUtil;
import com.thanos.common.utils.StdDSAEncoder;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * 类ECPublicKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 17:52
 */

public class ECPublicKey extends SecurePublicKey {

    /**
     * The parameters of the sm2p256v1 curve.
     */
    public static final ECDomainParameters CURVE;

    public static final ECParameterSpec CURVE_SPEC;

    public final ECPublicKeyParameters publicKeyParameters;

    public static final String ALGORITHM = "EC";

    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    public ECPublicKey(byte[] pubBytes) {
        this.pub = pubBytes;
        publicKeyParameters = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(pub), CURVE);
        this.publicKey = publicKeyFromBytes(pub);
    }

    @Override
    public byte[] getNodeId() {
        if (nodeId == null) {
            nodeId = Arrays.copyOfRange(pub, 1, pub.length);
        }
        return nodeId;
    }


    @Override
    public boolean verify(byte[] data, byte[] sig) {
        try {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, publicKeyParameters);
            BigInteger[] components = StdDSAEncoder.decode(sig);
            return signer.verifySignature(data, components[0], components[1]);
        } catch (Exception e) {
            logger.warn("ECPublicKey verify error!", e);
            return false;
        }
    }


    private static PublicKey publicKeyFromBytes(byte[] pubKeyBytes) {
        if (pubKeyBytes == null) {
            return null;
        } else {
            try {
                ECPoint w = CURVE.getCurve().decodePoint(pubKeyBytes);
                return KeyFactory.getInstance(ALGORITHM, CastleProvider.getBouncyInstance())
                        .generatePublic(new ECPublicKeySpec(w, CURVE_SPEC));
            } catch (InvalidKeySpecException ex) {
                throw new AssertionError("Assumed correct key spec statically", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new AssertionError("Assumed correct algorithm of ed pubKey", ex);
            }
        }
    }

    @Override
    public byte[] computeAddress(byte[] pubBytes) {
        return HashUtil.sha3omit12(
                Arrays.copyOfRange(pubBytes, 1, pubBytes.length));
    }
}
