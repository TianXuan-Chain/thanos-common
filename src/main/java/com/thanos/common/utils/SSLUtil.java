package com.thanos.common.utils;

import com.thanos.common.crypto.CastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

/**
 * 类SSLUtil.java的实现描述：
 *
 * @author xuhao create on 2021/3/17 14:41
 */

public class SSLUtil {

    private static final Logger logger = LoggerFactory.getLogger(SSLUtil.class);
    private static SecureRandom secureRandom;

    static {
        if (OperateSystemUtil.isLinuxPlatform()) {
            try {
                secureRandom = SecureRandom.getInstance("NATIVEPRNGNONBLOCKING");
            } catch (NoSuchAlgorithmException e) {
                logger.error("SSLUtil create secureRandom instance failed. ", e);
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e1) {
                }
                System.exit(1);
            }
        } else {
            secureRandom = new SecureRandom();
        }
    }

    public static SSLContext loadSSLContext(String keyPath, String certsPath) {
        SSLContext sslContext = null;
        try {
            //1.加载密钥管理器
            String providerName = CastleProvider.getJsseInstance().getName();

            KeyStore ks = KeyStoreUtil.getKeyStore(certsPath, keyPath);
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", providerName);
            keyMgrFact.init(ks, KeyStoreUtil.DEAFULT_PASSWORD.toCharArray());
            //2.加载信任库
            KeyStore tks = KeyStoreUtil.getTrustStore(certsPath);
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", providerName);
            trustMgrFact.init(tks);
            logger.info("TrustManagerFactory init success!");
            //3.初始化SSL_CONTEXT
            sslContext = SSLContext.getInstance("TLS", providerName);
            logger.info("SSLContext.getInstance success!");

            sslContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), secureRandom);
            logger.info("loadSSLContext! success!");
        } catch (Exception e) {
            logger.error("loadSSLContext error!", e);
            throw new RuntimeException(e);
        }
        return sslContext;
    }


    public static void main(String[] args) {
        try {
            final Set<String> algorithms = Security.getAlgorithms("SecureRandom");

            for (String algorithm : algorithms) {
                System.out.println(algorithm);
            }

            final String defaultAlgorithm = new SecureRandom().getAlgorithm();

            System.out.println("default: " + defaultAlgorithm);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
