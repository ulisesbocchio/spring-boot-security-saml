package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.Collections;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class SSOConfigurerTest {

    private ServiceProviderBuilder builder;
    private ServiceProviderEndpoints serviceProviderEndpoints;
    private SAMLSSOProperties properties;
    private AuthenticationManager authenticationManager;

    @Before
    public void setup() {
        properties = spy(new SAMLSSOProperties());
        serviceProviderEndpoints = spy(new ServiceProviderEndpoints());
        authenticationManager = mock(AuthenticationManager.class);
        builder = mock(ServiceProviderBuilder.class);
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

        verify(properties).getDefaultFailureUrl();
        verify(properties).getDefaultSuccessUrl();
        verify(properties).getDiscoveryProcessingUrl();
        verify(properties).getIdpSelectionPageUrl();
        verify(properties).getSsoHokProcessingUrl();
        verify(properties).getSsoLoginUrl();
        verify(properties).getSsoProcessingUrl();
        verify(properties).getProfileOptions();

        verify(successHandler).setDefaultTargetUrl(eq(properties.getDefaultSuccessUrl()));
        verify(failureHandler).setDefaultFailureUrl(eq(properties.getDefaultFailureUrl()));

        verify(ssoFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoFilter).setFilterProcessesUrl(eq(properties.getSsoProcessingUrl()));

        verify(ssoHoKFilter).setAuthenticationManager(eq(authenticationManager));
        verify(ssoHoKFilter).setAuthenticationSuccessHandler(eq(successHandler));
        verify(ssoHoKFilter).setAuthenticationFailureHandler(eq(failureHandler));
        verify(ssoHoKFilter).setFilterProcessesUrl(eq(properties.getSsoHokProcessingUrl()));

        verify(serviceProviderEndpoints).setSsoProcessingURL(properties.getSsoProcessingUrl());
        verify(serviceProviderEndpoints).setSsoHoKProcessingURL(properties.getSsoHokProcessingUrl());
        verify(serviceProviderEndpoints).setDefaultFailureURL(properties.getDefaultFailureUrl());
        verify(serviceProviderEndpoints).setDiscoveryProcessingURL(properties.getDiscoveryProcessingUrl());
        verify(serviceProviderEndpoints).setIdpSelectionPageURL(properties.getIdpSelectionPageUrl());
        verify(serviceProviderEndpoints).setSsoLoginURL(properties.getSsoLoginUrl());

        verify(discoveryFilter).setFilterProcessesUrl(eq(properties.getDiscoveryProcessingUrl()));
        verify(discoveryFilter).setIdpSelectionPath(eq(properties.getIdpSelectionPageUrl()));

        verify(entryPoint).setFilterProcessesUrl(eq(properties.getSsoLoginUrl()));
        ArgumentCaptor<WebSSOProfileOptions> optionsCaptor = ArgumentCaptor.forClass(WebSSOProfileOptions.class);
        verify(entryPoint).setDefaultProfileOptions(optionsCaptor.capture());
        WebSSOProfileOptions options = optionsCaptor.getValue();
        Assertions.assertThat(options.isAllowCreate()).isEqualTo(properties.getProfileOptions().getAllowCreate());
        Assertions.assertThat(options.getAllowedIDPs()).isEqualTo(properties.getProfileOptions().getAllowedIdps());
        Assertions.assertThat(options.getAssertionConsumerIndex()).isEqualTo(properties.getProfileOptions().getAssertionConsumerIndex());
        Assertions.assertThat(options.getAuthnContextComparison()).isEqualTo(properties.getProfileOptions().getAuthnContextComparison());
        Assertions.assertThat(options.getAuthnContexts()).isEqualTo(properties.getProfileOptions().getAuthnContexts());
        Assertions.assertThat(options.getBinding()).isEqualTo(properties.getProfileOptions().getBinding());
        Assertions.assertThat(options.getForceAuthN()).isEqualTo(properties.getProfileOptions().getForceAuthn());
        Assertions.assertThat(options.isIncludeScoping()).isEqualTo(properties.getProfileOptions().getIncludeScoping());
        Assertions.assertThat(options.getNameID()).isEqualTo(properties.getProfileOptions().getNameId());
        Assertions.assertThat(options.getPassive()).isEqualTo(properties.getProfileOptions().getPassive());
        Assertions.assertThat(options.getProviderName()).isEqualTo(properties.getProfileOptions().getProviderName());
        Assertions.assertThat(options.getProxyCount()).isEqualTo(properties.getProfileOptions().getProxyCount());
        Assertions.assertThat(options.getRelayState()).isEqualTo(properties.getProfileOptions().getRelayState());

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
        WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
        profileOptions.setAllowCreate(true);
        profileOptions.setAllowedIDPs(Collections.singleton("allowedIdps"));
        profileOptions.setAssertionConsumerIndex(999);
        profileOptions.setAuthnContextComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        profileOptions.setAuthnContexts(Collections.singleton("contexts"));
        profileOptions.setBinding("binding");
        profileOptions.setForceAuthN(true);
        profileOptions.setIncludeScoping(true);
        profileOptions.setNameID("nameId");
        profileOptions.setPassive(true);
        profileOptions.setProviderName("providerName");
        profileOptions.setProxyCount(null);
        profileOptions.setRelayState("relayState");

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

        verify(properties, never()).getDefaultFailureUrl();
        verify(properties, never()).getDefaultSuccessUrl();
        verify(properties, never()).getDiscoveryProcessingUrl();
        verify(properties, never()).getIdpSelectionPageUrl();
        verify(properties, never()).getSsoHokProcessingUrl();
        verify(properties, never()).getSsoLoginUrl();
        verify(properties, never()).getSsoProcessingUrl();
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
        ArgumentCaptor<WebSSOProfileOptions> optionsCaptor = ArgumentCaptor.forClass(WebSSOProfileOptions.class);
        verify(entryPoint).setDefaultProfileOptions(optionsCaptor.capture());
        WebSSOProfileOptions options = optionsCaptor.getValue();
        Assertions.assertThat(options.isAllowCreate()).isEqualTo(true);
        Assertions.assertThat(options.getAllowedIDPs()).containsExactly("allowedIdps");
        Assertions.assertThat(options.getAssertionConsumerIndex()).isEqualTo(999);
        Assertions.assertThat(options.getAuthnContextComparison()).isEqualTo(AuthnContextComparisonTypeEnumeration.MINIMUM);
        Assertions.assertThat(options.getAuthnContexts()).containsExactly("contexts");
        Assertions.assertThat(options.getBinding()).isEqualTo("binding");
        Assertions.assertThat(options.getForceAuthN()).isEqualTo(true);
        Assertions.assertThat(options.isIncludeScoping()).isEqualTo(true);
        Assertions.assertThat(options.getNameID()).isEqualTo("nameId");
        Assertions.assertThat(options.getPassive()).isEqualTo(true);
        Assertions.assertThat(options.getProviderName()).isEqualTo("providerName");
        Assertions.assertThat(options.getProxyCount()).isEqualTo(null);
        Assertions.assertThat(options.getRelayState()).isEqualTo("relayState");

        verify(builder).setSharedObject(eq(SAMLProcessingFilter.class), eq(ssoFilter));
        verify(builder).setSharedObject(eq(SAMLWebSSOHoKProcessingFilter.class), eq(ssoHoKFilter));
        verify(builder).setSharedObject(eq(SAMLDiscovery.class), eq(discoveryFilter));
        verify(builder).setSharedObject(eq(SAMLEntryPoint.class), eq(entryPoint));

    }

    @SuppressWarnings("unchecked")
    @Test
    public void configure_custom_entry_point() throws Exception {
        SSOConfigurer configurer = spy(new SSOConfigurer());
        SAMLProcessingFilter ssoFilter = mock(SAMLProcessingFilter.class);
        when(configurer.createDefaultSamlProcessingFilter()).thenReturn(ssoFilter);
        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = mock(SAMLWebSSOHoKProcessingFilter.class);
        when(configurer.createDefaultSamlHoKProcessingFilter()).thenReturn(ssoHoKFilter);
        SAMLDiscovery discoveryFilter = mock(SAMLDiscovery.class);
        when(configurer.createDefaultSamlDiscoveryFilter()).thenReturn(discoveryFilter);
        when(configurer.createDefaultSamlEntryPoint()).thenThrow(IllegalStateException.class);
        SavedRequestAwareAuthenticationSuccessHandler successHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);
        SimpleUrlAuthenticationFailureHandler failureHandler = mock(SimpleUrlAuthenticationFailureHandler.class);
        WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
        profileOptions.setAllowCreate(true);
        profileOptions.setAllowedIDPs(Collections.singleton("allowedIdps"));
        profileOptions.setAssertionConsumerIndex(999);
        profileOptions.setAuthnContextComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        profileOptions.setAuthnContexts(Collections.singleton("contexts"));
        profileOptions.setBinding("binding");
        profileOptions.setForceAuthN(true);
        profileOptions.setIncludeScoping(true);
        profileOptions.setNameID("nameId");
        profileOptions.setPassive(true);
        profileOptions.setProviderName("providerName");
        profileOptions.setProxyCount(null);
        profileOptions.setRelayState("relayState");

        SAMLEntryPoint customEntryPoint = mock(SAMLEntryPoint.class);
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
                .ssoProcessingURL("/sso")
                .samlEntryPoint(customEntryPoint);
        configurer.configure(builder);

        verify(properties, never()).getDefaultFailureUrl();
        verify(properties, never()).getDefaultSuccessUrl();
        verify(properties, never()).getDiscoveryProcessingUrl();
        verify(properties, never()).getIdpSelectionPageUrl();
        verify(properties, never()).getSsoHokProcessingUrl();
        verify(properties, never()).getSsoLoginUrl();
        verify(properties, never()).getSsoProcessingUrl();
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

        verify(customEntryPoint).setFilterProcessesUrl(eq("/login"));
        ArgumentCaptor<WebSSOProfileOptions> optionsCaptor = ArgumentCaptor.forClass(WebSSOProfileOptions.class);
        verify(customEntryPoint).setDefaultProfileOptions(optionsCaptor.capture());
        WebSSOProfileOptions options = optionsCaptor.getValue();
        Assertions.assertThat(options.isAllowCreate()).isEqualTo(true);
        Assertions.assertThat(options.getAllowedIDPs()).containsExactly("allowedIdps");
        Assertions.assertThat(options.getAssertionConsumerIndex()).isEqualTo(999);
        Assertions.assertThat(options.getAuthnContextComparison()).isEqualTo(AuthnContextComparisonTypeEnumeration.MINIMUM);
        Assertions.assertThat(options.getAuthnContexts()).containsExactly("contexts");
        Assertions.assertThat(options.getBinding()).isEqualTo("binding");
        Assertions.assertThat(options.getForceAuthN()).isEqualTo(true);
        Assertions.assertThat(options.isIncludeScoping()).isEqualTo(true);
        Assertions.assertThat(options.getNameID()).isEqualTo("nameId");
        Assertions.assertThat(options.getPassive()).isEqualTo(true);
        Assertions.assertThat(options.getProviderName()).isEqualTo("providerName");
        Assertions.assertThat(options.getProxyCount()).isEqualTo(null);
        Assertions.assertThat(options.getRelayState()).isEqualTo("relayState");

        verify(builder).setSharedObject(eq(SAMLProcessingFilter.class), eq(ssoFilter));
        verify(builder).setSharedObject(eq(SAMLWebSSOHoKProcessingFilter.class), eq(ssoHoKFilter));
        verify(builder).setSharedObject(eq(SAMLDiscovery.class), eq(discoveryFilter));
        verify(builder).setSharedObject(eq(SAMLEntryPoint.class), eq(customEntryPoint));

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

        verify(properties, never()).getDefaultFailureUrl();
        verify(properties, never()).getDefaultSuccessUrl();
        verify(properties, never()).getDiscoveryProcessingUrl();
        verify(properties, never()).getIdpSelectionPageUrl();
        verify(properties, never()).getSsoHokProcessingUrl();
        verify(properties, never()).getSsoLoginUrl();
        verify(properties, never()).getSsoProcessingUrl();
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