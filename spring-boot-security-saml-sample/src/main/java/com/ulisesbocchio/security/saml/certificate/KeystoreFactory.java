package com.ulisesbocchio.security.saml.certificate;

import lombok.SneakyThrows;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;

/**
 * @author Ulises Bocchio
 */
public class KeystoreFactory {

    private ResourceLoader resourceLoader;

    public KeystoreFactory() {
        resourceLoader = new DefaultResourceLoader();
    }

    public KeystoreFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @SneakyThrows
    public KeyStore loadKeystore(String certResourceLocation, String privateKeyResourceLocation, String alias, String keyPassword) {
        KeyStore keystore = createEmptyKeystore();
        X509Certificate cert = loadCert(certResourceLocation);
        RSAPrivateKey privateKey = loadPrivateKey(privateKeyResourceLocation);
        addKeyToKeystore(keystore, cert, privateKey, alias, keyPassword);
        return keystore;
    }

    @SneakyThrows
    public void addKeyToKeystore(KeyStore keyStore, X509Certificate cert, RSAPrivateKey privateKey, String alias, String password) {
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password.toCharArray());
        Certificate[] certificateChain = {cert};
        keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
    }

    @SneakyThrows
    public KeyStore createEmptyKeystore() {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "".toCharArray());
        return keyStore;
    }

    @SneakyThrows
    public X509Certificate loadCert(String certLocation) {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        Resource certRes = resourceLoader.getResource(certLocation);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certRes.getInputStream());
        return cert;
    }

    @SneakyThrows
    public RSAPrivateKey loadPrivateKey(String privateKeyLocation) {
        Resource keyRes = resourceLoader.getResource(privateKeyLocation);
        byte[] keyBytes = StreamUtils.copyToByteArray(keyRes.getInputStream());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    public void setResourceLoader(DefaultResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException {
        ResourceLoader rl = new DefaultResourceLoader();
        KeystoreFactory kf = new KeystoreFactory(rl);
        KeyStore keyStore = kf.loadKeystore("classpath:/localhost.cert", "classpath:/localhost.key.der", "ping", "123456");

        JKSKeyManager keyManager = new JKSKeyManager(keyStore, Collections.singletonMap("ping", "123456"), "ping");
        keyManager.getAvailableCredentials().forEach(System.out::println);
        System.out.println(keyManager.getDefaultCredential().getPrivateKey().getFormat());
        System.out.println(keyManager.getDefaultCredential().getPublicKey().getFormat());

    }
}
