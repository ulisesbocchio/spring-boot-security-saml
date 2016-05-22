package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

import java.util.Collections;
import java.util.Map;

/**
 * Configuration Properties for {@link org.springframework.security.saml.key.KeyManager}
 *
 * @author Ulises Bocchio
 */
@Data
public class KeyManagerProperties {
    /**
     * Specify a PEM certificate location. Used in conjunction with privateKeyDerLocation.
     */
    String publicKeyPemLocation;

    /**
     * Specify a DER private key location. Used in conjunction with publicKeyPemLocation.
     */
    String privateKeyDerLocation;

    /**
     * The location of KeyStore resource. If used, privateKeyDerLocation and privateKeyDerLocation are ignored.
     */
    String storeLocation;

    /**
     * The KeyStore password. Not relevant when using privateKeyDerLocation and privateKeyDerLocation.
     */
    String storePass;

    /**
     * They KeyStore private key passwords by key name.
     */
    Map<String, String> keyPasswords = Collections.singletonMap("localhost", "");

    /**
     * The default key name to use for encryption.
     */
    String defaultKey = "localhost";
}
