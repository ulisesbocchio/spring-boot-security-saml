package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.KeyManagerProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.resource.KeystoreFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.KeyManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class KeyManagerConfigurerTest {
    private ServiceProviderSecurityBuilder builder;
    private KeyManagerProperties keyManagerProperties;

    @Before
    public void setup() {
        SAMLSSOProperties properties = mock(SAMLSSOProperties.class);
        keyManagerProperties = mock(KeyManagerProperties.class);
        when(properties.getKeyManager()).thenReturn(keyManagerProperties);
//        when(keyManagerProperties.getDefaultKey()).thenReturn("default");
//        when(keyManagerProperties.getKeyPasswords()).thenReturn(Collections.singletonMap("default", "password"));
//        when(keyManagerProperties.getPrivateKeyDerLocation()).thenReturn("classpath:localhost:key.der");
//        when(keyManagerProperties.getPublicKeyPemLocation()).thenReturn("classpath:localhost.cert");
//        when(keyManagerProperties.getStoreLocation()).thenReturn("classpath:KeyStore.jks");
//        when(keyManagerProperties.getStorePass()).thenReturn("storePass");
        builder = mock(ServiceProviderSecurityBuilder.class);
        when(builder.getSharedObject(KeyManager.class)).thenReturn(null);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
        when(builder.getSharedObject(ResourceLoader.class)).thenReturn(new DefaultResourceLoader());
    }

    @Test
    public void init() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(KeyManager.class));
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
    }

    @Test
    public void configure() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(KeyManager.class), any(KeyManager.class));
    }

    @Test
    public void configure_forBean() throws Exception {
        KeyManager keyManager = mock(KeyManager.class);
        when(builder.getSharedObject(KeyManager.class)).thenReturn(keyManager);
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(keyManager, keyManagerProperties);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        KeyManager keyManager = mock(KeyManager.class);
        KeyManagerConfigurer configurer = new KeyManagerConfigurer(keyManager);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(KeyManager.class), eq(keyManager));
        verifyZeroInteractions(keyManager, keyManagerProperties);
    }

    @Test
    public void testArguments_keystore() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer
                .keyStore(new KeystoreFactory(new DefaultResourceLoader()).createEmptyKeystore());
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<KeyManager> providerCaptor = ArgumentCaptor.forClass(KeyManager.class);
        verify(builder).setSharedObject(eq(KeyManager.class), providerCaptor.capture());
        verify(keyManagerProperties).getDefaultKey();
        verify(keyManagerProperties).getKeyPasswords();
        verify(keyManagerProperties).getPrivateKeyDerLocation();
        verify(keyManagerProperties).getPublicKeyPemLocation();
        verify(keyManagerProperties).getStoreLocation();
        verify(keyManagerProperties).getStorePass();
        assertThat(providerCaptor.getValue()).isNotNull();
        KeyManager keyManager = providerCaptor.getValue();
        assertThat(keyManager.getAvailableCredentials()).isEmpty();
    }

    @Test
    public void testArguments_keystore_location() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer
                .storeLocation("classpath:KeyStore.jks")
                .storePass("password")
                .defaultKey("default")
                .keyPassword("default", "password");
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<KeyManager> providerCaptor = ArgumentCaptor.forClass(KeyManager.class);
        verify(builder).setSharedObject(eq(KeyManager.class), providerCaptor.capture());
        verify(keyManagerProperties, never()).getDefaultKey();
        verify(keyManagerProperties, never()).getKeyPasswords();
        verify(keyManagerProperties, never()).getStoreLocation();
        verify(keyManagerProperties, never()).getStorePass();
        verify(keyManagerProperties).getPrivateKeyDerLocation();
        verify(keyManagerProperties).getPublicKeyPemLocation();
        assertThat(providerCaptor.getValue()).isNotNull();
        KeyManager keyManager = providerCaptor.getValue();
        assertThat(keyManager.getAvailableCredentials()).containsExactly("default");
        assertThat(keyManager.getDefaultCredential().getEntityId()).isEqualTo("default");
        assertThat(keyManager.getDefaultCredentialName()).isEqualTo("default");
    }

    @Test
    public void testArguments_der_and_pem() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer
                .publicKeyPEMLocation("classpath:localhost.cert")
                .privateKeyDERLocation("classpath:localhost.key.der")
                .defaultKey("localhost")
                .keyPassword("localhost", "");
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<KeyManager> providerCaptor = ArgumentCaptor.forClass(KeyManager.class);
        verify(builder).setSharedObject(eq(KeyManager.class), providerCaptor.capture());
        verify(keyManagerProperties, never()).getDefaultKey();
        verify(keyManagerProperties, never()).getKeyPasswords();
        verify(keyManagerProperties, never()).getPrivateKeyDerLocation();
        verify(keyManagerProperties, never()).getPublicKeyPemLocation();
        verify(keyManagerProperties).getStoreLocation();
        verify(keyManagerProperties).getStorePass();
        assertThat(providerCaptor.getValue()).isNotNull();
        KeyManager keyManager = providerCaptor.getValue();
        assertThat(keyManager.getAvailableCredentials()).containsExactly("localhost");
        assertThat(keyManager.getDefaultCredential().getEntityId()).isEqualTo("localhost");
        assertThat(keyManager.getDefaultCredentialName()).isEqualTo("localhost");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testArguments_der_and_pem_error() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer
                .publicKeyPEMLocation("classpath:localhost.cert")
                .privateKeyDERLocation("classpath:localhost.key.der");
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<KeyManager> providerCaptor = ArgumentCaptor.forClass(KeyManager.class);
        verify(builder).setSharedObject(eq(KeyManager.class), providerCaptor.capture());
        verify(keyManagerProperties, never()).getDefaultKey();
        verify(keyManagerProperties, never()).getKeyPasswords();
        verify(keyManagerProperties, never()).getPrivateKeyDerLocation();
        verify(keyManagerProperties, never()).getPublicKeyPemLocation();
        verify(keyManagerProperties).getStoreLocation();
        verify(keyManagerProperties).getStorePass();
        assertThat(providerCaptor.getValue()).isNotNull();
        KeyManager keyManager = providerCaptor.getValue();
        assertThat(keyManager.getAvailableCredentials()).containsExactly("localhost");
        assertThat(keyManager.getDefaultCredential().getEntityId()).isEqualTo("localhost");
        assertThat(keyManager.getDefaultCredentialName()).isEqualTo("localhost");
    }

    @Test
    public void testProperties() throws Exception {
        KeyManagerConfigurer configurer = new KeyManagerConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<KeyManager> providerCaptor = ArgumentCaptor.forClass(KeyManager.class);
        verify(builder).setSharedObject(eq(KeyManager.class), providerCaptor.capture());
        assertThat(providerCaptor.getValue()).isNotNull();
        KeyManager keyManager = providerCaptor.getValue();
        assertThat(keyManager).isExactlyInstanceOf(EmptyKeyManager.class);
    }

}