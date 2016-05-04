package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.resource.KeystoreFactory;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Configures Single Sign On filter for SAML Service Provider
 */
public class KeyManagerConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private KeyManager keyManager;
    private KeyManager keyManagerBean;
    private KeyStore keyStore;
    private String publicKeyPEMLocation;
    private String privateKeyDERLocation;
    private String storeLocation;
    private String storePass;
    private Map<String, String> keyPasswords;
    private String defaultKey;
    private SAMLSsoProperties.KeystoreConfiguration config;
    private KeystoreFactory keystoreFactory;
    private ResourceLoader resourceLoader;

    public KeyManagerConfigurer(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public KeyManagerConfigurer() {

    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        keyManagerBean = builder.getSharedObject(KeyManager.class);
        config = builder.getSharedObject(SAMLSsoProperties.class).getKeystore();
        resourceLoader = builder.getSharedObject(ResourceLoader.class);
        keystoreFactory = new KeystoreFactory(resourceLoader);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        privateKeyDERLocation = Optional.ofNullable(privateKeyDERLocation).orElseGet(config::getPrivateKeyDERLocation);
        publicKeyPEMLocation = Optional.ofNullable(publicKeyPEMLocation).orElseGet(config::getPublicKeyPEMLocation);
        defaultKey = Optional.ofNullable(defaultKey).orElseGet(config::getDefaultKey);
        keyPasswords = Optional.ofNullable(keyPasswords).orElseGet(config::getKeyPasswords);
        storePass = Optional.ofNullable(storePass).orElseGet(config::getStorePass);
        storeLocation = Optional.ofNullable(storeLocation).orElseGet(config::getStoreLocation);

        if(keyManagerBean == null) {
            if(keyManager == null) {
                if(keyStore == null) {
                    if(storeLocation == null) {
                        if(privateKeyDERLocation == null || publicKeyPEMLocation == null) {
                            keyManager = new EmptyKeyManager();
                        } else {
                            keyStore = keystoreFactory.loadKeystore(publicKeyPEMLocation, privateKeyDERLocation, defaultKey, "");
                            keyManager = new JKSKeyManager(keyStore, keyPasswords, defaultKey);
                        }
                    } else {
                        keyManager = new JKSKeyManager(resourceLoader.getResource(storeLocation), storePass, keyPasswords, defaultKey);
                    }
                } else {
                    keyManager = new JKSKeyManager(keyStore, keyPasswords, defaultKey);
                }
            }
        }
        builder.setSharedObject(KeyManager.class, keyManager);
    }

    public KeyManagerConfigurer keyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
        return this;
    }

    public KeyManagerConfigurer publicKeyPEMLocation(String publicKeyPEMLocation) {
        this.publicKeyPEMLocation = publicKeyPEMLocation;
        return this;
    }

    public KeyManagerConfigurer privateKeyDERLocation(String privateKeyDERLocation) {
        this.privateKeyDERLocation = privateKeyDERLocation;
        return this;
    }

    public KeyManagerConfigurer storeLocation(String storeLocation) {
        this.storeLocation = storeLocation;
        return this;
    }

    public KeyManagerConfigurer storePass(String storePass) {
        this.storePass = storePass;
        return this;
    }

    public KeyManagerConfigurer keyPasswords(Map<String, String> keyPasswords) {
        this.keyPasswords = keyPasswords;
        return this;
    }

    public KeyManagerConfigurer keyPassword(String key, String password) {
        if(keyPasswords == null) {
            keyPasswords = new HashMap<>();
        }
        keyPasswords.put(key, password);
        return this;
    }

    public KeyManagerConfigurer defaultKey(String defaultKey) {
        this.defaultKey = defaultKey;
        return this;
    }
}
