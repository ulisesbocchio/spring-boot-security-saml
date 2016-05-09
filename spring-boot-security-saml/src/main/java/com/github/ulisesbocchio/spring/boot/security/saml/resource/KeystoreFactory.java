package com.github.ulisesbocchio.spring.boot.security.saml.resource;

import lombok.SneakyThrows;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Class for internal use of this Spring Boot Plugin. It's used to create {@link KeyStore} objects based on different
 * resources such as JKS keystore files, X509 PEM certificates, and RSA DER private keys.
 *
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

    /**
     * Based on a public certificate, private key, alias and password, this method will load the certificate and private key as an entry
     * into a newly created keystore, and it will set the provided alias and password to the keystore entry.
     * @param certResourceLocation
     * @param privateKeyResourceLocation
     * @param alias
     * @param keyPassword
     * @return
     */
    @SneakyThrows
    public KeyStore loadKeystore(String certResourceLocation, String privateKeyResourceLocation, String alias, String keyPassword) {
        KeyStore keystore = createEmptyKeystore();
        X509Certificate cert = loadCert(certResourceLocation);
        RSAPrivateKey privateKey = loadPrivateKey(privateKeyResourceLocation);
        addKeyToKeystore(keystore, cert, privateKey, alias, keyPassword);
        return keystore;
    }

    /**
     * Based on a public certificate, private key, alias and password, this method will load the certificate and private key as an entry
     * into the keystore, and it will set the provided alias and password to the keystore entry.
     * @param keyStore
     * @param cert
     * @param privateKey
     * @param alias
     * @param password
     */
    @SneakyThrows
    public void addKeyToKeystore(KeyStore keyStore, X509Certificate cert, RSAPrivateKey privateKey, String alias, String password) {
        KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password.toCharArray());
        Certificate[] certificateChain = {cert};
        keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
    }

    /**
     * Returns an empty KeyStore object.
     * @return
     */
    @SneakyThrows
    public KeyStore createEmptyKeystore() {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, "".toCharArray());
        return keyStore;
    }

    /**
     * Given a resource location it loads a PEM X509 certificate.
     * @param certLocation
     * @return
     */
    @SneakyThrows
    public X509Certificate loadCert(String certLocation) {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        Resource certRes = resourceLoader.getResource(certLocation);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certRes.getInputStream());
        return cert;
    }

    /**
     * Given a resource location it loads a DER RSA private Key.
     * @param privateKeyLocation
     * @return
     */
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
}
