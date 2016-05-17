package com.github.ulisesbocchio.spring.boot.security.saml.resource;

import static org.junit.Assert.*;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * @author Ulises Bocchio, Sergio.U.Bocchio@Disney.com (BOCCS002)
 */
public class KeystoreFactoryTest {

    @Test
    public void loadKeystore() throws Exception {
        KeystoreFactory keystoreFactory = new KeystoreFactory(new DefaultResourceLoader());
        KeyStore keyStore = keystoreFactory.loadKeystore("classpath:/localhost.cert", "classpath:/localhost.key.der", "alias", "password");
        Assertions.assertThat(keyStore.containsAlias("alias")).isTrue();
        Enumeration<String> aliases = keyStore.aliases();
        Assertions.assertThat(aliases.hasMoreElements()).isTrue();
        Assertions.assertThat(aliases.nextElement()).isEqualTo("alias");
        Assertions.assertThat(aliases.hasMoreElements()).isFalse();
        Certificate cert = keyStore.getCertificate("alias");
        Assertions.assertThat(cert.getType()).isEqualTo("X.509");
        cert.verify(cert.getPublicKey());
    }

}