package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.WebSSOProfile;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class WebSSOProfileConfigurerTest {
    private ServiceProviderBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);
    }

    @Test
    public void init() throws Exception {
        WebSSOProfileConfigurer configurer = new WebSSOProfileConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(WebSSOProfile.class));
    }

    @Test
    public void configure() throws Exception {
        WebSSOProfileConfigurer configurer = spy(new WebSSOProfileConfigurer());
        WebSSOProfile profile = mock(WebSSOProfile.class);
        when(configurer.createDefaultWebSSOProfile()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(WebSSOProfile.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        WebSSOProfileConfigurer configurer = spy(new WebSSOProfileConfigurer());
        WebSSOProfile profile = mock(WebSSOProfile.class);
        when(builder.getSharedObject(WebSSOProfile.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfile();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        WebSSOProfile profile = mock(WebSSOProfile.class);
        WebSSOProfileConfigurer configurer = spy(new WebSSOProfileConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultWebSSOProfile();
        verify(builder).setSharedObject(WebSSOProfile.class, profile);
        verifyZeroInteractions(profile);
    }
}