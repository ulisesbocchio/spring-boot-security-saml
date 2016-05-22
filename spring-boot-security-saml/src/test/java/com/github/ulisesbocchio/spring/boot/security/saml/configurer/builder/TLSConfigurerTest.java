package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.TLSProperties;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;

import java.util.Set;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@SuppressWarnings("unchecked")
public class TLSConfigurerTest {

    private ServiceProviderSecurityBuilder builder;
    private TLSProperties tlsConfig;
    private SAMLSSOProperties properties;

    @Before
    public void setup() {
        properties = mock(SAMLSSOProperties.class);
        tlsConfig = spy(new TLSProperties());
        when(properties.getTls()).thenReturn(tlsConfig);
        builder = mock(ServiceProviderSecurityBuilder.class);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        TLSConfigurer configurer = new TLSConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
        verify(properties).getTls();
    }

    @Test
    public void configure_defaults() throws Exception {
        TLSConfigurer configurer = spy(new TLSConfigurer());
        TLSProtocolConfigurer tlsProtocolConfigurer = mock(TLSProtocolConfigurer.class);
        when(configurer.createDefaultTlsProtocolConfigurer()).thenReturn(tlsProtocolConfigurer);
        configurer.init(builder);
        configurer.configure(builder);
        verify(tlsConfig).getProtocolName();
        verify(tlsConfig).getProtocolPort();
        verify(tlsConfig).getSslHostnameVerification();
        verify(tlsConfig).getTrustedKeys();
        verify(builder).setSharedObject(eq(TLSProtocolConfigurer.class), eq(tlsProtocolConfigurer));
        verify(tlsProtocolConfigurer).setProtocolName(eq(tlsConfig.getProtocolName()));
        verify(tlsProtocolConfigurer).setProtocolPort(eq(tlsConfig.getProtocolPort()));
        verify(tlsProtocolConfigurer).setSslHostnameVerification(eq(tlsConfig.getSslHostnameVerification()));
        verify(tlsProtocolConfigurer).setTrustedKeys(eq(tlsConfig.getTrustedKeys()));
    }

    @Test
    public void configure_custom() throws Exception {
        TLSConfigurer configurer = spy(new TLSConfigurer());
        TLSProtocolConfigurer tlsProtocolConfigurer = mock(TLSProtocolConfigurer.class);
        when(configurer.createDefaultTlsProtocolConfigurer()).thenReturn(tlsProtocolConfigurer);
        configurer
                .protocolName("protocol")
                .protocolPort(9999)
                .sslHostnameVerification("strict")
                .trustedKeys("one", "two");
        configurer.init(builder);
        configurer.configure(builder);
        verify(tlsConfig, never()).getProtocolName();
        verify(tlsConfig, never()).getProtocolPort();
        verify(tlsConfig, never()).getSslHostnameVerification();
        verify(tlsConfig, never()).getTrustedKeys();
        verify(builder).setSharedObject(eq(TLSProtocolConfigurer.class), eq(tlsProtocolConfigurer));
        verify(tlsProtocolConfigurer).setProtocolName(eq("protocol"));
        verify(tlsProtocolConfigurer).setProtocolPort(eq(9999));
        verify(tlsProtocolConfigurer).setSslHostnameVerification(eq("strict"));
        verify(tlsProtocolConfigurer).setTrustedKeys((Set<String>) argThat(contains("one", "two")));
    }

}