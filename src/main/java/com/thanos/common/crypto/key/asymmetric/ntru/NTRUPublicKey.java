package com.thanos.common.crypto.key.asymmetric.ntru;

import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.HashUtil;
import net.sf.ntru.sign.NtruSign;
import net.sf.ntru.sign.SignatureParameters;
import net.sf.ntru.sign.SignaturePublicKey;

import java.util.Arrays;

/**
 * NTRUPublicKey.java description：
 *
 * @Author lemon819 create on 2020-11-19 17:22:33
 */
public class NTRUPublicKey extends SecurePublicKey {
    public static final String ALGORITHM = "NTRU";

    public NTRUPublicKey(byte[] pubBytes) {
        this.pub = pubBytes;
        this.signaturePublicKey = publicKeyFromBytes(pub);
    }

    @Override
    public byte[] getNodeId() {
        if (nodeId == null) {
            nodeId = HashUtil.sha512(this.pub);
        }
        return nodeId;
    }

    @Override
    public boolean verify(byte[] data, byte[] sig) {
        NtruSign sign = new NtruSign(SignatureParameters.APR2011_439_PROD);
        sign.initVerify(signaturePublicKey);
        return sign.verify(data, sig, signaturePublicKey);
    }


    private static SignaturePublicKey publicKeyFromBytes(byte[] pubKeyBytes) {
        if (pubKeyBytes == null) {
            return null;
        } else {
            return new SignaturePublicKey(pubKeyBytes);
        }
    }

    @Override
    public byte[] computeAddress(byte[] pubBytes) {
        return HashUtil.sha3omit12(
                Arrays.copyOfRange(pubBytes, 0, pubBytes.length));
    }
}
