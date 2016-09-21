package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.AuthenticationProviderProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.user.SimpleSAMLUserDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.saml.SAMLAuthenticationProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationProviderConfigurerTest {

    private ServiceProviderBuilder builder;
    private AuthenticationProviderProperties authProviderProperties;

    @Before
    public void setup() {
        SAMLSSOProperties properties = mock(SAMLSSOProperties.class);
        authProviderProperties = mock(AuthenticationProviderProperties.class);
        when(properties.getAuthenticationProvider()).thenReturn(authProviderProperties);
        when(authProviderProperties.isExcludeCredential()).thenReturn(false);
        when(authProviderProperties.isForcePrincipalAsString()).thenReturn(false);
        builder = mock(ServiceProviderBuilder.class);
        when(builder.getSharedObject(SAMLAuthenticationProvider.class)).thenReturn(null);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
    }

    @Test
    public void init() throws Exception {
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(SAMLAuthenticationProvider.class));
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
    }

    @Test
    public void configure() throws Exception {
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLAuthenticationProvider.class), any(SAMLAuthenticationProvider.class));
    }

    @Test
    public void configure_forBean() throws Exception {
        SAMLAuthenticationProvider samlAuthenticationProvider = mock(SAMLAuthenticationProvider.class);
        when(builder.getSharedObject(SAMLAuthenticationProvider.class)).thenReturn(samlAuthenticationProvider);
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(samlAuthenticationProvider, authProviderProperties);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        SAMLAuthenticationProvider samlAuthenticationProvider = mock(SAMLAuthenticationProvider.class);
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer(samlAuthenticationProvider);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SAMLAuthenticationProvider.class), eq(samlAuthenticationProvider));
        verifyZeroInteractions(samlAuthenticationProvider, authProviderProperties);
    }

    @Test
    public void testArguments() throws Exception {
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer();
        configurer
                .excludeCredential(true)
                .forcePrincipalAsString(false);
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<SAMLAuthenticationProvider> providerCaptor = ArgumentCaptor.forClass(SAMLAuthenticationProvider.class);
        verify(builder).setSharedObject(eq(SAMLAuthenticationProvider.class), providerCaptor.capture());
        verifyZeroInteractions(authProviderProperties);
        assertThat(providerCaptor.getValue()).isNotNull();
        SAMLAuthenticationProvider authenticationProvider = providerCaptor.getValue();
        assertThat(authenticationProvider.isExcludeCredential()).isTrue();
        assertThat(authenticationProvider.isForcePrincipalAsString()).isFalse();
        assertThat(authenticationProvider.getUserDetails()).isExactlyInstanceOf(SimpleSAMLUserDetailsService.class);
    }

    @Test
    public void testProperties() throws Exception {
        AuthenticationProviderConfigurer configurer = new AuthenticationProviderConfigurer();
        configurer.init(builder);
        configurer.configure(builder);
        ArgumentCaptor<SAMLAuthenticationProvider> providerCaptor = ArgumentCaptor.forClass(SAMLAuthenticationProvider.class);
        verify(builder).setSharedObject(eq(SAMLAuthenticationProvider.class), providerCaptor.capture());
        verify(authProviderProperties).isExcludeCredential();
        verify(authProviderProperties).isForcePrincipalAsString();
        assertThat(providerCaptor.getValue()).isNotNull();
        SAMLAuthenticationProvider authenticationProvider = providerCaptor.getValue();
        assertThat(authenticationProvider.isExcludeCredential()).isFalse();
        assertThat(authenticationProvider.isForcePrincipalAsString()).isFalse();
        assertThat(authenticationProvider.getUserDetails()).isExactlyInstanceOf(SimpleSAMLUserDetailsService.class);
    }
}