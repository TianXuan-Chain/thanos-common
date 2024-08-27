package com.thanos.common.crypto.key.asymmetric.sm;

import com.thanos.common.crypto.CastleProvider;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.HashUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * 类SMPublicKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 19:11
 */

public class SMPublicKey extends SecurePublicKey {

    public SMPublicKey(byte[] pubBytes) {
        this.pub = pubBytes;
        this.publicKey = publicKeyFromBytes(pub);
    }

    /**
     * The parameters of the sm2p256v1 curve.
     */
    public static final ECDomainParameters CURVE;

    public static final ECParameterSpec CURVE_SPEC;

    public static final String SM2_WITH_SM3 = GMObjectIdentifiers.sm2sign_with_sm3.toString();

    public static final String ALGORITHM = "EC";

    static {
        X9ECParameters params = GMNamedCurves.getByName("sm2p256v1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
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
            Signature signature = Signature.getInstance(SM2_WITH_SM3, "BC");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sig);
        } catch (Exception e) {
            logger.warn("SMPublicKey verify error!", e);
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
