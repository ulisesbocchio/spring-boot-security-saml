package com.github.ulisesbocchio.spring.boot.security.saml.resource;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.io.FileNotFoundException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Ulises Bocchio, Sergio.U.Bocchio@Disney.com (BOCCS002)
 */
public class KeystoreFactoryTest {

    @Test
    public void loadKeystore() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        KeyStore keyStore = keystoreFactory.loadKeystore("classpath:/localhost.cert", "classpath:/localhost.key.der", "alias", "password");
        assertThat(keyStore.containsAlias("alias")).isTrue();
        assertThat(keyStore.size()).isEqualTo(1);
        Certificate cert = keyStore.getCertificate("alias");
        assertThat(cert.getType()).isEqualTo("X.509");
        cert.verify(cert.getPublicKey());
        Key key = keyStore.getKey("alias", "password".toCharArray());
        assertThat(key.getAlgorithm()).isEqualTo("RSA");
        assertThat(key.getFormat()).isEqualTo("PKCS#8");
    }

    @Test
    public void loadCert() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        Certificate cert = keystoreFactory.loadCert("classpath:/localhost.cert");
        assertThat(cert.getType()).isEqualTo("X.509");
        cert.verify(cert.getPublicKey());
    }

    @Test(expected = FileNotFoundException.class)
    public void loadCert_notFound() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        Certificate cert = keystoreFactory.loadCert("classpath:/not_found.cert");
    }

    @Test(expected = CertificateParsingException.class)
    public void loadCert_invalid() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        Certificate cert = keystoreFactory.loadCert("classpath:/localhost.key.der");
    }

    @Test
    public void loadKey() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        RSAPrivateKey key = keystoreFactory.loadPrivateKey("classpath:/localhost.key.der");
        assertThat(key.getAlgorithm()).isEqualTo("RSA");
        assertThat(key.getFormat()).isEqualTo("PKCS#8");
    }

    @Test(expected = FileNotFoundException.class)
    public void loadKey_notFound() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        RSAPrivateKey key = keystoreFactory.loadPrivateKey("classpath:/not_found.key.der");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void loadKey_invalid() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        RSAPrivateKey key = keystoreFactory.loadPrivateKey("classpath:/localhost.cert");
    }

    @Test
    public void createEmptyKeystore() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        KeyStore keyStore = keystoreFactory.createEmptyKeystore();
        assertThat(keyStore.size()).isEqualTo(0);

    }

}