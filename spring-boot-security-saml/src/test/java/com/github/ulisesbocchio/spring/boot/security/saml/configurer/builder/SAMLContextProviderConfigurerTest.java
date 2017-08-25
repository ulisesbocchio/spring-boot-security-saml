package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.*;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class SAMLContextProviderConfigurerTest {

    private ServiceProviderBuilder builder;
    private SAMLSSOProperties properties;
    private SAMLContextProviderProperties contextProviderProperties;
    private SAMLContextProviderLBProperties contextProviderLBProperties;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);

        properties = mock(SAMLSSOProperties.class);
        contextProviderProperties = spy(new SAMLContextProviderProperties());
        contextProviderLBProperties = spy(new SAMLContextProviderLBProperties());
        when(properties.getContextProvider()).thenReturn(contextProviderProperties);
        when(contextProviderProperties.getLb()).thenReturn(contextProviderLBProperties);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        SAMLContextProviderConfigurer configurer = new SAMLContextProviderConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
    }

    @Test
    public void configure() throws Exception {
        SAMLContextProviderConfigurer configurer = spy(new SAMLContextProviderConfigurer());
        SAMLContextProvider provider = mock(SAMLContextProvider.class);
        when(configurer.createDefaultSamlContextProvider()).thenReturn(provider);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLContextProvider.class), eq(provider));
    }

    @Test
    public void configure_forBean() throws Exception {
        SAMLContextProviderConfigurer configurer = spy(new SAMLContextProviderConfigurer());
        SAMLContextProvider provider = mock(SAMLContextProvider.class);
        when(builder.getSharedObject(SAMLContextProvider.class)).thenReturn(provider);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSamlContextProvider();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions( provider);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        SAMLContextProvider provider = mock(SAMLContextProvider.class);
        SAMLContextProviderConfigurer configurer = spy(new SAMLContextProviderConfigurer(provider));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSamlContextProvider();
        verify(builder).setSharedObject(SAMLContextProvider.class, provider);
        verifyZeroInteractions( provider);
    }

}