package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileHoKConsumerConfigurerTest {
    private ServiceProviderBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);
    }

    @Test
    public void init() throws Exception {
        WebSSOProfileHoKConsumerConfigurer configurer = new WebSSOProfileHoKConsumerConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(WebSSOProfileConsumerHoKImpl.class));
    }

    @Test
    public void configure() throws Exception {
        WebSSOProfileHoKConsumerConfigurer configurer = spy(new WebSSOProfileHoKConsumerConfigurer());
        WebSSOProfileConsumerHoKImpl profile = mock(WebSSOProfileConsumerHoKImpl.class);
        when(configurer.createDefaultWebSSOProfileConsumerHoK()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(WebSSOProfileConsumerHoKImpl.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        WebSSOProfileHoKConsumerConfigurer configurer = spy(new WebSSOProfileHoKConsumerConfigurer());
        WebSSOProfileConsumerHoKImpl profile = mock(WebSSOProfileConsumerHoKImpl.class);
        when(builder.getSharedObject(WebSSOProfileConsumerHoKImpl.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileConsumerHoK();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        WebSSOProfileConsumerHoKImpl profile = mock(WebSSOProfileConsumerHoKImpl.class);
        WebSSOProfileHoKConsumerConfigurer configurer = spy(new WebSSOProfileHoKConsumerConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfileConsumerHoK();
        verify(builder).setSharedObject(WebSSOProfileConsumerHoKImpl.class, profile);
        verifyZeroInteractions(profile);
    }
}