package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class SSOConfigurerTest {

    private ServiceProviderSecurityBuilder builder;
    private ServiceProviderEndpoints serviceProviderEndpoints;
    private SAMLSSOProperties properties;
    private AuthenticationManager authenticationManager;

    @Before
    public void setup() {
        properties = spy(new SAMLSSOProperties());
        serviceProviderEndpoints = spy(new ServiceProviderEndpoints());
        authenticationManager = mock(AuthenticationManager.class);
        builder = mock(ServiceProviderSecurityBuilder.class);
        when(builder.getSharedObject(ServiceProviderEndpoints.class)).thenReturn(serviceProviderEndpoints);
        when(builder.getSharedObject(SAMLSSOProperties.class)).thenReturn(properties);
        when(builder.getSharedObject(AuthenticationManager.class)).thenReturn(authenticationManager);
    }

    @Test
    public void init() throws Exception {
        SSOConfigurer configurer = new SSOConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(ServiceProviderEndpoints.class));
        verify(builder).getSharedObject(eq(SAMLSSOProperties.class));
        verify(builder).getSharedObject(eq(AuthenticationManager.class));
    }

    @Test
    public void configure_defaults() throws Exception {
        SSOConfigurer configurer = spy(new SSOConfigurer());
        SAMLProcessingFilter ssoFilter = mock(SAMLProcessingFilter.class);
        when(configurer.createDefaultSamlProcessingFilter()).thenReturn(ssoFilter);
        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = mock(SAMLWebSSOHoKProcessingFilter.class);
        when(configurer.createDefaultSamlHoKProcessingFilter()).thenReturn(ssoHoKFilter);
        SAMLDiscovery discoveryFilter = mock(SAMLDiscovery.class);
        when(configurer.createDefaultSamlDiscoveryFilter()).thenReturn(discoveryFilter);
        SAMLEntryPoint entryPoint = mock(SAMLEntryPoint.class);
        when(configurer.createDefaultSamlEntryPoint()).thenReturn(entryPoint);
        SavedRequestAwareAuthenticationSuccessHandler successHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);
        when(configurer.createDefaultSuccessHandler()).thenReturn(successHandler);
        SimpleUrlAuthenticationFailureHandler failureHandler = mock(SimpleUrlAuthenticationFailureHandler.class);
        when(configurer.createDefaultFailureHandler()).thenReturn(failureHandler);
        configurer.init(builder);
        configurer.configure(builder);

        verify(properties).getDefaultFailureURL();
        verify(properties).getDefaultSuccessURL();
        verify(properties).getDiscoveryProcessingURL();
        verify(properties).getIdpSelectionPageURL();
        verify(properties).getSsoHoKProcessingURL();
        verify(properties).getSsoLoginURL();
        verify(properties).getSsoProcessingURL();
        verify(properties).getProfileOptions();

        verify(successHandler).setDefaultTargetUrl(eq(properties.getDefaultSuccessURL()));
        verify(failureHandler).setDefaultFailureUrl(eq(properties.getDefaultFailureURL()));

        verify(ssoFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoFilter).setFilterProcessesUrl(eq(properties.getSsoProcessingURL()));

        verify(ssoHoKFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoHoKFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoHoKFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoHoKFilter).setFilterProcessesUrl(eq(properties.getSsoHoKProcessingURL()));

        verify(serviceProviderEndpoints).setSsoProcessingURL(properties.getSsoProcessingURL());
        verify(serviceProviderEndpoints).setSsoHoKProcessingURL(properties.getSsoHoKProcessingURL());
        verify(serviceProviderEndpoints).setDefaultFailureURL(properties.getDefaultFailureURL());
        verify(serviceProviderEndpoints).setDiscoveryProcessingURL(properties.getDiscoveryProcessingURL());
        verify(serviceProviderEndpoints).setIdpSelectionPageURL(properties.getIdpSelectionPageURL());
        verify(serviceProviderEndpoints).setSsoLoginURL(properties.getSsoLoginURL());

        verify(discoveryFilter).setFilterProcessesUrl(eq(properties.getDiscoveryProcessingURL()));
        verify(discoveryFilter).setIdpSelectionPath(eq(properties.getIdpSelectionPageURL()));

        verify(entryPoint).setFilterProcessesUrl(eq(properties.getSsoLoginURL()));
        verify(entryPoint).setDefaultProfileOptions(eq(properties.getProfileOptions()));

        verify(builder).setSharedObject(eq(SAMLProcessingFilter.class), eq(ssoFilter));
        verify(builder).setSharedObject(eq(SAMLWebSSOHoKProcessingFilter.class), eq(ssoHoKFilter));
        verify(builder).setSharedObject(eq(SAMLDiscovery.class), eq(discoveryFilter));
        verify(builder).setSharedObject(eq(SAMLEntryPoint.class), eq(entryPoint));

    }

    @Test
    public void configure_custom() throws Exception {
        SSOConfigurer configurer = spy(new SSOConfigurer());
        SAMLProcessingFilter ssoFilter = mock(SAMLProcessingFilter.class);
        when(configurer.createDefaultSamlProcessingFilter()).thenReturn(ssoFilter);
        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = mock(SAMLWebSSOHoKProcessingFilter.class);
        when(configurer.createDefaultSamlHoKProcessingFilter()).thenReturn(ssoHoKFilter);
        SAMLDiscovery discoveryFilter = mock(SAMLDiscovery.class);
        when(configurer.createDefaultSamlDiscoveryFilter()).thenReturn(discoveryFilter);
        SAMLEntryPoint entryPoint = mock(SAMLEntryPoint.class);
        when(configurer.createDefaultSamlEntryPoint()).thenReturn(entryPoint);
        SavedRequestAwareAuthenticationSuccessHandler successHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);
        SimpleUrlAuthenticationFailureHandler failureHandler = mock(SimpleUrlAuthenticationFailureHandler.class);
        WebSSOProfileOptions profileOptions = mock(WebSSOProfileOptions.class);

        configurer.init(builder);
        configurer
                .defaultSuccessURL("/success")
                .failureHandler(failureHandler)
                .successHandler(successHandler)
                .defaultFailureURL("/failure")
                .discoveryProcessingURL("/discovery")
                .enableSsoHoK(true)
                .idpSelectionPageURL("/idp")
                .profileOptions(profileOptions)
                .ssoHoKProcessingURL("/hok")
                .ssoLoginURL("/login")
                .ssoProcessingURL("/sso");
        configurer.configure(builder);

        verify(properties, never()).getDefaultFailureURL();
        verify(properties, never()).getDefaultSuccessURL();
        verify(properties, never()).getDiscoveryProcessingURL();
        verify(properties, never()).getIdpSelectionPageURL();
        verify(properties, never()).getSsoHoKProcessingURL();
        verify(properties, never()).getSsoLoginURL();
        verify(properties, never()).getSsoProcessingURL();
        verify(properties, never()).getProfileOptions();

        verify(successHandler, never()).setDefaultTargetUrl(eq("/success"));
        verify(failureHandler, never()).setDefaultFailureUrl(eq("/failure"));

        verify(ssoFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoFilter).setFilterProcessesUrl(eq("/sso"));

        verify(ssoHoKFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoHoKFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoHoKFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoHoKFilter).setFilterProcessesUrl(eq("/hok"));

        verify(serviceProviderEndpoints).setSsoProcessingURL("/sso");
        verify(serviceProviderEndpoints).setSsoHoKProcessingURL("/hok");
        verify(serviceProviderEndpoints).setDefaultFailureURL("/failure");
        verify(serviceProviderEndpoints).setDiscoveryProcessingURL("/discovery");
        verify(serviceProviderEndpoints).setIdpSelectionPageURL("/idp");
        verify(serviceProviderEndpoints).setSsoLoginURL("/login");

        verify(discoveryFilter).setFilterProcessesUrl(eq("/discovery"));
        verify(discoveryFilter).setIdpSelectionPath(eq("/idp"));

        verify(entryPoint).setFilterProcessesUrl(eq("/login"));
        verify(entryPoint).setDefaultProfileOptions(eq(profileOptions));

        verify(builder).setSharedObject(eq(SAMLProcessingFilter.class), eq(ssoFilter));
        verify(builder).setSharedObject(eq(SAMLWebSSOHoKProcessingFilter.class), eq(ssoHoKFilter));
        verify(builder).setSharedObject(eq(SAMLDiscovery.class), eq(discoveryFilter));
        verify(builder).setSharedObject(eq(SAMLEntryPoint.class), eq(entryPoint));

    }

    @Test
    public void configure_custom_noHoK() throws Exception {
        SSOConfigurer configurer = spy(new SSOConfigurer());
        SAMLProcessingFilter ssoFilter = mock(SAMLProcessingFilter.class);
        when(configurer.createDefaultSamlProcessingFilter()).thenReturn(ssoFilter);
        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = mock(SAMLWebSSOHoKProcessingFilter.class);
        when(configurer.createDefaultSamlHoKProcessingFilter()).thenReturn(ssoHoKFilter);
        SAMLDiscovery discoveryFilter = mock(SAMLDiscovery.class);
        when(configurer.createDefaultSamlDiscoveryFilter()).thenReturn(discoveryFilter);
        SAMLEntryPoint entryPoint = mock(SAMLEntryPoint.class);
        when(configurer.createDefaultSamlEntryPoint()).thenReturn(entryPoint);
        SavedRequestAwareAuthenticationSuccessHandler successHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);
        SimpleUrlAuthenticationFailureHandler failureHandler = mock(SimpleUrlAuthenticationFailureHandler.class);
        WebSSOProfileOptions profileOptions = mock(WebSSOProfileOptions.class);

        configurer.init(builder);
        configurer
                .defaultSuccessURL("/success")
                .failureHandler(failureHandler)
                .successHandler(successHandler)
                .defaultFailureURL("/failure")
                .discoveryProcessingURL("/discovery")
                .enableSsoHoK(false)
                .idpSelectionPageURL("/idp")
                .profileOptions(profileOptions)
                .ssoHoKProcessingURL("/hok")
                .ssoLoginURL("/login")
                .ssoProcessingURL("/sso");
        configurer.configure(builder);

        verify(properties, never()).getDefaultFailureURL();
        verify(properties, never()).getDefaultSuccessURL();
        verify(properties, never()).getDiscoveryProcessingURL();
        verify(properties, never()).getIdpSelectionPageURL();
        verify(properties, never()).getSsoHoKProcessingURL();
        verify(properties, never()).getSsoLoginURL();
        verify(properties, never()).getSsoProcessingURL();
        verify(properties, never()).getProfileOptions();

        verify(successHandler, never()).setDefaultTargetUrl(eq("/success"));
        verify(failureHandler, never()).setDefaultFailureUrl(eq("/failure"));

        verify(ssoFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoFilter).setFilterProcessesUrl(eq("/sso"));

        verify(ssoHoKFilter, never()).setAuthenticationManager(eq(authenticationManager));
        verify(ssoHoKFilter, never()).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoHoKFilter, never()).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoHoKFilter, never()).setFilterProcessesUrl(eq("/hok"));

        verify(serviceProviderEndpoints).setSsoProcessingURL("/sso");
        verify(serviceProviderEndpoints, never()).setSsoHoKProcessingURL("/hok");
        verify(serviceProviderEndpoints).setDefaultFailureURL("/failure");
        verify(serviceProviderEndpoints).setDiscoveryProcessingURL("/discovery");
        verify(serviceProviderEndpoints).setIdpSelectionPageURL("/idp");
        verify(serviceProviderEndpoints).setSsoLoginURL("/login");

        verify(discoveryFilter).setFilterProcessesUrl(eq("/discovery"));
        verify(discoveryFilter).setIdpSelectionPath(eq("/idp"));

        verify(entryPoint).setFilterProcessesUrl(eq("/login"));
        verify(entryPoint).setDefaultProfileOptions(eq(profileOptions));

        verify(builder).setSharedObject(eq(SAMLProcessingFilter.class), eq(ssoFilter));
        verify(builder).setSharedObject(eq(SAMLWebSSOHoKProcessingFilter.class), eq(null));
        verify(builder).setSharedObject(eq(SAMLDiscovery.class), eq(discoveryFilter));
        verify(builder).setSharedObject(eq(SAMLEntryPoint.class), eq(entryPoint));

    }

}