package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileConsumerConfigurerTest {

    private ServiceProviderBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);
    }

    @Test
    public void init() throws Exception {
        WebSSOProfileConsumerConfigurer configurer = new WebSSOProfileConsumerConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(WebSSOProfileConsumer.class));
    }

    @Test
    public void configure() throws Exception {
        WebSSOProfileConsumerConfigurer configurer = spy(new WebSSOProfileConsumerConfigurer());
        WebSSOProfileConsumer profile = mock(WebSSOProfileConsumer.class);
        when(configurer.createWebSSOProfileConsumer()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(WebSSOProfileConsumer.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        WebSSOProfileConsumerConfigurer configurer = spy(new WebSSOProfileConsumerConfigurer());
        WebSSOProfileConsumer profile = mock(WebSSOProfileConsumer.class);
        when(builder.getSharedObject(WebSSOProfileConsumer.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createWebSSOProfileConsumer();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        WebSSOProfileConsumer profile = mock(WebSSOProfileConsumer.class);
        WebSSOProfileConsumerConfigurer configurer = spy(new WebSSOProfileConsumerConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createWebSSOProfileConsumer();
        verify(builder).setSharedObject(WebSSOProfileConsumer.class, profile);
        verifyZeroInteractions(profile);
    }
}