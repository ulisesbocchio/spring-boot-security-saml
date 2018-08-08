package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfileHoKImpl;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileHoKConfigurerTest {
    private ServiceProviderBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);
    }

    @Test
    public void init() throws Exception {
        WebSSOProfileHoKConfigurer configurer = new WebSSOProfileHoKConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(WebSSOProfileHoKImpl.class));
    }

    @Test
    public void configure() throws Exception {
        WebSSOProfileHoKConfigurer configurer = spy(new WebSSOProfileHoKConfigurer());
        WebSSOProfileHoKImpl profile = mock(WebSSOProfileHoKImpl.class);
        when(configurer.createDefaultWebSSOProfileHoK()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(WebSSOProfileHoKImpl.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        WebSSOProfileHoKConfigurer configurer = spy(new WebSSOProfileHoKConfigurer());
        WebSSOProfileHoKImpl profile = mock(WebSSOProfileHoKImpl.class);
        when(builder.getSharedObject(WebSSOProfileHoKImpl.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileHoK();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        WebSSOProfileHoKImpl profile = mock(WebSSOProfileHoKImpl.class);
        WebSSOProfileHoKConfigurer configurer = spy(new WebSSOProfileHoKConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileHoK();
        verify(builder).setSharedObject(WebSSOProfileHoKImpl.class, profile);
        verifyZeroInteractions(profile);
    }
}