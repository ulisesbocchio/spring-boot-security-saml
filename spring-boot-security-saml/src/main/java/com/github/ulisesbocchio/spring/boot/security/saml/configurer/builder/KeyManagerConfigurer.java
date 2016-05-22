package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.KeyManagerProperties;
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
 * Builder configurer that takes care of configuring/customizing the {@link KeyManager} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link KeyManager} bean is defined, priority goes to a custom KeyManager provided explicitly
 * to this configurer through the constructor. And if not provided through the constructor, a default implementation is
 * instantiated that is configurable through the DSL methods.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getKeyManager()} if no custom KeyManager
 * is provided, for some DSL methods if they are not used. In other words, the user is able to configure the KeyManager
 * through the following properties:
 * <pre>
 *     saml.sso.keyManager.publicKeyPemLocation
 *     saml.sso.keyManager.privateKeyDerLocation
 *     saml.sso.keyManager.storeLocation
 *     saml.sso.keyManager.storePass
 *     saml.sso.keyManager.keyPasswords
 *     saml.sso.keyManager.defaultKey
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
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
    private KeyManagerProperties config;
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
        config = builder.getSharedObject(SAMLSSOProperties.class).getKeyManager();
        resourceLoader = builder.getSharedObject(ResourceLoader.class);
        keystoreFactory = new KeystoreFactory(resourceLoader);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (keyManagerBean == null) {
            if (keyManager == null) {
                privateKeyDERLocation = Optional.ofNullable(privateKeyDERLocation).orElseGet(config::getPrivateKeyDerLocation);
                publicKeyPEMLocation = Optional.ofNullable(publicKeyPEMLocation).orElseGet(config::getPublicKeyPemLocation);
                defaultKey = Optional.ofNullable(defaultKey).orElseGet(config::getDefaultKey);
                keyPasswords = Optional.ofNullable(keyPasswords).orElseGet(config::getKeyPasswords);
                storePass = Optional.ofNullable(storePass).orElseGet(config::getStorePass);
                storeLocation = Optional.ofNullable(storeLocation).orElseGet(config::getStoreLocation);
                if (keyStore == null) {
                    if (storeLocation == null) {
                        if (privateKeyDERLocation == null || publicKeyPEMLocation == null) {
                            keyManager = new EmptyKeyManager();
                        } else {
                            validateDefaultKeyAndPasswords();
                            keyStore = keystoreFactory.loadKeystore(publicKeyPEMLocation, privateKeyDERLocation, defaultKey, "");
                            keyManager = new JKSKeyManager(keyStore, keyPasswords, defaultKey);
                        }
                    } else {
                        validateDefaultKeyAndPasswords();
                        keyManager = new JKSKeyManager(resourceLoader.getResource(storeLocation), storePass, keyPasswords, defaultKey);
                    }
                } else {
                    keyManager = new JKSKeyManager(keyStore, keyPasswords, defaultKey);
                }
            }
            builder.setSharedObject(KeyManager.class, keyManager);
        }
    }

    private void validateDefaultKeyAndPasswords() {
        if(defaultKey == null || defaultKey.trim().equals("")) {
            throw new IllegalArgumentException("'defaultKey' cannot be null or empty.");
        }
        if(keyPasswords == null || keyPasswords.isEmpty()) {
            throw new IllegalArgumentException("'keyPasswords' cannot be null or empty.");
        }
    }

    /**
     * Set the actual {@link KeyStore} object to use. Takes precedence over {@link #publicKeyPEMLocation(String)},
     * {@link #privateKeyDERLocation(String)}, and {@link #storeLocation(String)}.
     *
     * @param keyStore the KeyStore to use.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer keyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
        return this;
    }

    /**
     * If no {@link KeyStore} is provided, specify a PEM certificate location. Used in conjunction with
     * {@link #privateKeyDERLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.publicKeyPemLocation
     * </pre>
     * </p>
     *
     * @param publicKeyPEMLocation the location of the PEM public key certificate.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer publicKeyPEMLocation(String publicKeyPEMLocation) {
        this.publicKeyPEMLocation = publicKeyPEMLocation;
        return this;
    }

    /**
     * If no {@link KeyStore} is provided, specify a DER private key location. Used in conjunction with
     * {@link #publicKeyPEMLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.privateKeyDerLocation
     * </pre>
     * </p>
     *
     * @param privateKeyDERLocation the location of the DER private key.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer privateKeyDERLocation(String privateKeyDERLocation) {
        this.privateKeyDERLocation = privateKeyDERLocation;
        return this;
    }

    /**
     * If not {@link KeyStore} is provided, specify the KeyStore location. Takes precedence over {@link
     * #publicKeyPEMLocation(String)} and
     * {@link #privateKeyDERLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.storeLocation
     * </pre>
     * </p>
     *
     * @param storeLocation the location of the KeyStore.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer storeLocation(String storeLocation) {
        this.storeLocation = storeLocation;
        return this;
    }

    /**
     * Specify the {@link KeyStore} password. Not relevant if using {@link #publicKeyPEMLocation(String)} and
     * {@link #privateKeyDERLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.storePass
     * </pre>
     * </p>
     *
     * @param storePass the KeyStore password.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer storePass(String storePass) {
        this.storePass = storePass;
        return this;
    }

    /**
     * Specify the passwords of the keys stored in the {@link KeyStore}. Not relevant if using {@link
     * #publicKeyPEMLocation(String)} and
     * {@link #privateKeyDERLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.keyPasswords
     * </pre>
     * </p>
     *
     * @param keyPasswords
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer keyPasswords(Map<String, String> keyPasswords) {
        this.keyPasswords = keyPasswords;
        return this;
    }

    /**
     * Alternative to {@link #keyPasswords} when only 1 (one) key is present in the {@link KeyStore}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.keyPasswords
     * </pre>
     * </p>
     *
     * @param key      the key name.
     * @param password the key password.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer keyPassword(String key, String password) {
        if (keyPasswords == null) {
            keyPasswords = new HashMap<>();
        }
        keyPasswords.put(key, password);
        return this;
    }

    /**
     * Sets the default key to use for encryption. Not relevant if using {@link #publicKeyPEMLocation(String)} and
     * {@link #privateKeyDERLocation(String)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.keyManager.defaultKey
     * </pre>
     * </p>
     *
     * @param defaultKey the default key name.
     * @return this configurer for further customization
     */
    public KeyManagerConfigurer defaultKey(String defaultKey) {
        this.defaultKey = defaultKey;
        return this;
    }
}
