package com.thanos.common;

import com.thanos.common.crypto.key.asymmetric.SecureKey;
import com.thanos.common.crypto.key.symmetric.CipherKey;
import org.spongycastle.util.encoders.Hex;

/**
 * Main.java description：
 *
 * @Author laiyiyu create on 2021-01-26 10:33:07
 */
public class Main {
    public static void main(String[] args) {
        try {
            if (args.length == 2) {
                String algorithm = args[0];
                int shardingNumber = Integer.parseInt(args[1]);
                SecureKey secureKey = SecureKey.getInstance(algorithm, shardingNumber);
                System.out.println("#"+algorithm+"\n" +
                        "nodeIdPrivateKey = "+Hex.toHexString(secureKey.getPrivKeyBytes())+"\n" +
                        "nodeId = "+Hex.toHexString(secureKey.getNodeId())+"\n" +
                        "publicKey = "+ Hex.toHexString(secureKey.getPubKey()));
            } else if (args.length == 1) {
                String algorithm = args[0];
                CipherKey cipherKey = CipherKey.getInstance(algorithm);
                System.out.println("#"+algorithm+"\n" +
                        "nodeEncryptKey = "+Hex.toHexString(cipherKey.getKeyBytes()));
            } else {
                throw new RuntimeException("invalid args count. please input like 'ECDSA 1' or  'AES' ");
            }
        } catch (Exception e) {
            throw new RuntimeException("thanos-common generate Keys failed. e:", e);
        }
    }
}
