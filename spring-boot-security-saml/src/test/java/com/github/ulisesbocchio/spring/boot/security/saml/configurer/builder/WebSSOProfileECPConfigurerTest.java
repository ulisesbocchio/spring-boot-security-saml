package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileECPConfigurerTest {
    private ServiceProviderSecurityBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderSecurityBuilder.class);
    }

    @Test
    public void init() throws Exception {
        WebSSOProfileECPConfigurer configurer = new WebSSOProfileECPConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(WebSSOProfileECPImpl.class));
    }

    @Test
    public void configure() throws Exception {
        WebSSOProfileECPConfigurer configurer = spy(new WebSSOProfileECPConfigurer());
        WebSSOProfileECPImpl profile = mock(WebSSOProfileECPImpl.class);
        when(configurer.createDefaultWebSSOProfileECP()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(WebSSOProfileECPImpl.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        WebSSOProfileECPConfigurer configurer = spy(new WebSSOProfileECPConfigurer());
        WebSSOProfileECPImpl profile = mock(WebSSOProfileECPImpl.class);
        when(builder.getSharedObject(WebSSOProfileECPImpl.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileECP();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        WebSSOProfileECPImpl profile = mock(WebSSOProfileECPImpl.class);
        WebSSOProfileECPConfigurer configurer = spy(new WebSSOProfileECPConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileECP();
        verify(builder).setSharedObject(WebSSOProfileECPImpl.class, profile);
        verifyZeroInteractions(profile);
    }
}