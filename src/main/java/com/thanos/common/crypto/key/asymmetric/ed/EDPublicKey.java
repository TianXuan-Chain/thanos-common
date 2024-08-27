package com.thanos.common.crypto.key.asymmetric.ed;

import com.thanos.common.crypto.CastleProvider;
import com.thanos.common.crypto.key.asymmetric.SecurePublicKey;
import com.thanos.common.utils.ByteUtil;
import com.thanos.common.utils.HashUtil;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * 类EDPublicKey.java的实现描述：
 *
 * @author xuhao create on 2020/11/18 18:05
 */

public class EDPublicKey extends SecurePublicKey {

    public static final String ALGORITHM = "EdDSA";

    public static final String ED25519 = "Ed25519";

    private static final String Ed25519PubKeyPrefix = "302a300506032b6570032100";//ed25519公钥前缀

    public EDPublicKey(byte[] pubBytes) {
        this.pub = pubBytes;
        this.publicKey = publicKeyFromBytes(pub);
    }


    @Override
    public byte[] getNodeId() {
        if (nodeId == null) {
            byte[] pubBytes = pubBytesWithoutFormat(this.pub);
            nodeId = ByteUtil.merge(pubBytes, pubBytes);
        }
        return nodeId;
    }


    @Override
    public boolean verify(byte[] data, byte[] sig) {
        try {
            Signature signature = Signature.getInstance(ED25519, "BC");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sig);
        } catch (Exception e) {
            logger.warn("EDPublicKey verify error!", e);
            return false;
        }
    }


    private static PublicKey publicKeyFromBytes(byte[] pubKeyBytes) {
        if (pubKeyBytes == null) {
            return null;
        } else {
            try {
                return KeyFactory.getInstance(ALGORITHM, CastleProvider.getBouncyInstance())
                        .generatePublic(new X509EncodedKeySpec(formatPublic(pubKeyBytes)));
            } catch (InvalidKeySpecException ex) {
                throw new AssertionError("Assumed correct key spec statically", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new AssertionError("Assumed correct algorithm of ed pubKey", ex);

            }
        }
    }

    //公钥去掉prefix
    private static byte[] pubBytesWithoutFormat(byte[] pubBytes) {
        if (pubBytes == null) {
            return null;
        }
        String pubKeyStr = Hex.toHexString(pubBytes);
        if (pubKeyStr.startsWith(Ed25519PubKeyPrefix)) {
            pubKeyStr = pubKeyStr.substring(Ed25519PubKeyPrefix.length());
        }
        return Hex.decode(pubKeyStr);
    }


    //公钥标准化，统一加上Ed25519PubKeyPrefix前缀
    private static byte[] formatPublic(byte[] pubKeyBytes) {
        if (pubKeyBytes == null) {
            return null;
        }
        String pubKeyStr = Hex.toHexString(pubKeyBytes);
        if (!pubKeyStr.startsWith(Ed25519PubKeyPrefix)) {
            pubKeyStr = Ed25519PubKeyPrefix + pubKeyStr;
        }
        return Hex.decode(pubKeyStr);
    }

    @Override
    public byte[] computeAddress(byte[] pubBytes) {
        return HashUtil.sha3omit12(
                Arrays.copyOfRange(pubBytes, 0, pubBytes.length));
    }

}
