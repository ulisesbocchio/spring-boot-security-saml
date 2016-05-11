package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@RunWith(MockitoJUnitRunner.class)
public class ExtendedMetadataConfigurerTest {
    private ServiceProviderSecurityBuilder builder;
    private ExtendedMetadata extendedMetadataProperties;

    @Before
    public void setup() {
        SAMLSSOProperties properties = mock(SAMLSSOProperties.class);
        extendedMetadataProperties = mock(ExtendedMetadata.class);
        when(properties.getExtendedMetadata()).thenReturn(extendedMetadataProperties);
        when(extendedMetadataProperties.isLocal()).thenReturn(false);
        when(extendedMetadataProperties.isIdpDiscoveryEnabled()).thenReturn(false);
        when(extendedMetadataProperties.isEcpEnabled()).thenReturn(false);
        when(extendedMetadataProperties.isSignMetadata()).thenReturn(false);
        when(extendedMetadataProperties.isRequireLogoutRequestSigned()).thenReturn(false);
        when(extendedMetadataProperties.isRequireLogoutResponseSigned()).thenReturn(false);
        when(extendedMetadataProperties.isRequireArtifactResolveSigned()).thenReturn(false);
        when(extendedMetadataProperties.isSupportUnsolicitedResponse()).thenReturn(false);
        when(extendedMetadataProperties.getAlias()).thenReturn("default");
        when(extendedMetadataProperties.getIdpDiscoveryURL()).thenReturn("default");
        when(extendedMetadataProperties.getIdpDiscoveryResponseURL()).thenReturn("default");
        when(extendedMetadataProperties.getSecurityProfile()).thenReturn("default");
        when(extendedMetadataProperties.getSslSecurityProfile()).thenReturn("default");
        when(extendedMetadataProperties.getSslHostnameVerification()).thenReturn("default");
        when(extendedMetadataProperties.getSigningKey()).thenReturn("default");
        when(extendedMetadataProperties.getSigningAlgorithm()).thenReturn("default");
        when(extendedMetadataProperties.getKeyInfoGeneratorName()).thenReturn("default");
        when(extendedMetadataProperties.getEncryptionKey()).thenReturn("default");
        when(extendedMetadataProperties.getTlsKey()).thenReturn("default");
        when(extendedMetadataProperties.getTrustedKeys()).thenReturn(Collections.singleton("default"));

        builder = mock(ServiceProviderSecurityBuilder.class);
        when(builder.getSharedObject(ExtendedMetadata.class)).thenReturn(null);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(ExtendedMetadata.class));
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
    }

    @Test
    public void configure() throws Exception {
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(ExtendedMetadata.class), any(ExtendedMetadata.class));
    }

    @Test
    public void configure_forBean() throws Exception {
        ExtendedMetadata extendedMetadata = mock(ExtendedMetadata.class);
        when(builder.getSharedObject(ExtendedMetadata.class)).thenReturn(extendedMetadata);
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(extendedMetadata, extendedMetadataProperties);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        ExtendedMetadata extendedMetadata = mock(ExtendedMetadata.class);
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer(extendedMetadata);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(ExtendedMetadata.class), eq(extendedMetadata));
        verifyZeroInteractions(extendedMetadata, extendedMetadataProperties);
    }

    @Test
    public void testArguments() throws Exception {
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer();
        configurer
                .local(true)
                .idpDiscoveryEnabled(true)
                .ecpEnabled(true)
                .signMetadata(true)
                .requireLogoutRequestSigned(true)
                .requireLogoutResponseSigned(true)
                .requireArtifactResolveSigned(true)
                .supportUnsolicitedResponse(true)
                .alias("prop")
                .idpDiscoveryURL("prop")
                .idpDiscoveryResponseURL("prop")
                .securityProfile("prop")
                .sslSecurityProfile("prop")
                .sslHostnameVerification("prop")
                .signingKey("prop")
                .signingAlgorithm("prop")
                .keyInfoGeneratorName("prop")
                .encryptionKey("prop")
                .tlsKey("prop")
                .trustedKeys("prop");
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<ExtendedMetadata> extendedMetadataCaptor = ArgumentCaptor.forClass(ExtendedMetadata.class);
        verify(builder).setSharedObject(eq(ExtendedMetadata.class), extendedMetadataCaptor.capture());
        verifyZeroInteractions(extendedMetadataProperties);
        assertThat(extendedMetadataCaptor.getValue()).isNotNull();
        ExtendedMetadata extendedMetadata = extendedMetadataCaptor.getValue();
        assertThat(extendedMetadata.isLocal()).isTrue();
        assertThat(extendedMetadata.isIdpDiscoveryEnabled()).isTrue();
        assertThat(extendedMetadata.isEcpEnabled()).isTrue();
        assertThat(extendedMetadata.isSignMetadata()).isTrue();
        assertThat(extendedMetadata.isRequireLogoutRequestSigned()).isTrue();
        assertThat(extendedMetadata.isRequireLogoutResponseSigned()).isTrue();
        assertThat(extendedMetadata.isRequireArtifactResolveSigned()).isTrue();
        assertThat(extendedMetadata.isSupportUnsolicitedResponse()).isTrue();
        assertThat(extendedMetadata.getAlias()).isEqualTo("prop");
        assertThat(extendedMetadata.getIdpDiscoveryURL()).isEqualTo("prop");
        assertThat(extendedMetadata.getIdpDiscoveryResponseURL()).isEqualTo("prop");
        assertThat(extendedMetadata.getSecurityProfile()).isEqualTo("prop");
        assertThat(extendedMetadata.getSslSecurityProfile()).isEqualTo("prop");
        assertThat(extendedMetadata.getSslHostnameVerification()).isEqualTo("prop");
        assertThat(extendedMetadata.getSigningKey()).isEqualTo("prop");
        assertThat(extendedMetadata.getSigningAlgorithm()).isEqualTo("prop");
        assertThat(extendedMetadata.getKeyInfoGeneratorName()).isEqualTo("prop");
        assertThat(extendedMetadata.getEncryptionKey()).isEqualTo("prop");
        assertThat(extendedMetadata.getTlsKey()).isEqualTo("prop");
        assertThat(extendedMetadata.getTrustedKeys()).containsExactly("prop");
    }

    @Test
    public void testProperties() throws Exception {
        ExtendedMetadataConfigurer configurer = new ExtendedMetadataConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(extendedMetadataProperties).isLocal();
        verify(extendedMetadataProperties).isIdpDiscoveryEnabled();
        verify(extendedMetadataProperties).isEcpEnabled();
        verify(extendedMetadataProperties).isSignMetadata();
        verify(extendedMetadataProperties).isRequireLogoutRequestSigned();
        verify(extendedMetadataProperties).isRequireLogoutResponseSigned();
        verify(extendedMetadataProperties).isRequireArtifactResolveSigned();
        verify(extendedMetadataProperties).isSupportUnsolicitedResponse();
        verify(extendedMetadataProperties).getAlias();
        verify(extendedMetadataProperties).getIdpDiscoveryURL();
        verify(extendedMetadataProperties).getIdpDiscoveryResponseURL();
        verify(extendedMetadataProperties).getSecurityProfile();
        verify(extendedMetadataProperties).getSslSecurityProfile();
        verify(extendedMetadataProperties).getSslHostnameVerification();
        verify(extendedMetadataProperties).getSigningKey();
        verify(extendedMetadataProperties).getSigningAlgorithm();
        verify(extendedMetadataProperties).getKeyInfoGeneratorName();
        verify(extendedMetadataProperties).getEncryptionKey();
        verify(extendedMetadataProperties).getTlsKey();
        verify(extendedMetadataProperties).getTrustedKeys();
        ArgumentCaptor<ExtendedMetadata> extendedMetadataCaptor = ArgumentCaptor.forClass(ExtendedMetadata.class);
        verify(builder).setSharedObject(eq(ExtendedMetadata.class), extendedMetadataCaptor.capture());
        verifyZeroInteractions(extendedMetadataProperties);
        assertThat(extendedMetadataCaptor.getValue()).isNotNull();
        ExtendedMetadata extendedMetadata = extendedMetadataCaptor.getValue();
        assertThat(extendedMetadata.isLocal()).isFalse();
        assertThat(extendedMetadata.isIdpDiscoveryEnabled()).isFalse();
        assertThat(extendedMetadata.isEcpEnabled()).isFalse();
        assertThat(extendedMetadata.isSignMetadata()).isFalse();
        assertThat(extendedMetadata.isRequireLogoutRequestSigned()).isFalse();
        assertThat(extendedMetadata.isRequireLogoutResponseSigned()).isFalse();
        assertThat(extendedMetadata.isRequireArtifactResolveSigned()).isFalse();
        assertThat(extendedMetadata.isSupportUnsolicitedResponse()).isFalse();
        assertThat(extendedMetadata.getAlias()).isEqualTo("default");
        assertThat(extendedMetadata.getIdpDiscoveryURL()).isEqualTo("default");
        assertThat(extendedMetadata.getIdpDiscoveryResponseURL()).isEqualTo("default");
        assertThat(extendedMetadata.getSecurityProfile()).isEqualTo("default");
        assertThat(extendedMetadata.getSslSecurityProfile()).isEqualTo("default");
        assertThat(extendedMetadata.getSslHostnameVerification()).isEqualTo("default");
        assertThat(extendedMetadata.getSigningKey()).isEqualTo("default");
        assertThat(extendedMetadata.getSigningAlgorithm()).isEqualTo("default");
        assertThat(extendedMetadata.getKeyInfoGeneratorName()).isEqualTo("default");
        assertThat(extendedMetadata.getEncryptionKey()).isEqualTo("default");
        assertThat(extendedMetadata.getTlsKey()).isEqualTo("default");
        assertThat(extendedMetadata.getTrustedKeys()).containsExactly("default");
    }
}