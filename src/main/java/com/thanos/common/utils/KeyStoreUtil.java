package com.thanos.common.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * 类KeyStoreUtil.java的实现描述：
 *
 * @author xuhao create on 2021/3/17 10:22
 */

public class KeyStoreUtil {

    public static final String DEAFULT_PASSWORD = "123456";

    public static KeyStore getKeyStore(String chainPem, String privateKeyPem) throws CertificateException, IOException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException {
        Certificate[] certificates = loadCertificates(chainPem);
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca-cert", certificates[0]);
        keyStore.setCertificateEntry("agency-cert", certificates[1]);
        keyStore.setCertificateEntry("node-cert", certificates[2]);
        keyStore.setKeyEntry("node-privateKey", privateKey, DEAFULT_PASSWORD.toCharArray(), new Certificate[]{certificates[2], certificates[1], certificates[0]});
        return keyStore;
    }

    public static KeyStore getTrustStore(String chainPem) throws CertificateException, IOException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException {
        Certificate[] certificates = loadCertificates(chainPem);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca-cert", certificates[0]);
        return trustStore;
    }

    public static Certificate[] loadCertificates(String certificateChainPem) throws CertificateException, NoSuchProviderException, FileNotFoundException {
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(certificateChainPem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            List<Certificate> certificates = new ArrayList<>(cf.generateCertificates(inputStream));
            return certificates.toArray(new Certificate[certificates.size()]);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                }
            }
        }
    }

    public static PrivateKey loadPrivateKey(String privateKeyPem) throws IOException {
        FileReader f = new FileReader(privateKeyPem);
        BufferedReader br = new BufferedReader(f);
        PEMParser pp = new PEMParser(br);

        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(pp.readObject());
        return new JcaPEMKeyConverter().getPrivateKey(pki);
    }
}
