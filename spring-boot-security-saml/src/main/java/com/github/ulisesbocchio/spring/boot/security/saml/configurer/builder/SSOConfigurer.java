package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.Optional;

/**
 * Configures Single Sign On filter for SAML Service Provider
 */
public class SSOConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String defaultSuccessURL;
    private AuthenticationSuccessHandler successHandler;
    private String defaultFailureURL;
    private AuthenticationFailureHandler failureHandler;
    private String ssoProcessingURL;
    private Boolean enableSsoHoK;
    private String discoveryProcessingURL;
    private String idpSelectionPageURL;
    private String ssoLoginURL;
    private WebSSOProfileOptions profileOptions;
    private AuthenticationManager authenticationManager;
    private SAMLSsoProperties config;
    private ServiceProviderEndpoints endpoints;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        config = builder.getSharedObject(SAMLSsoProperties.class);
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if(successHandler == null) {
            SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
            successRedirectHandler.setDefaultTargetUrl(Optional.ofNullable(defaultSuccessURL).orElseGet(config::getDefaultSuccessURL));
            successHandler = postProcess(successRedirectHandler);
        }

        if(failureHandler == null) {
            SimpleUrlAuthenticationFailureHandler authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();
            defaultFailureURL = Optional.ofNullable(defaultFailureURL).orElseGet(config::getDefaultFailureURL);
            endpoints.setDefaultFailureURL(defaultFailureURL);
            authenticationFailureHandler.setDefaultFailureUrl(defaultFailureURL);
            failureHandler = postProcess(authenticationFailureHandler);
        }


        SAMLProcessingFilter ssoFilter = new SAMLProcessingFilter();
        ssoFilter.setAuthenticationManager(authenticationManager);
        ssoFilter.setAuthenticationSuccessHandler(successHandler);
        ssoFilter.setAuthenticationFailureHandler(failureHandler);
        ssoProcessingURL = Optional.ofNullable(ssoProcessingURL).orElseGet(config::getSsoProcessingURL);
        endpoints.setSsoProcessingURL(ssoProcessingURL);
        ssoFilter.setFilterProcessesUrl(ssoProcessingURL);
        builder.setSharedObject(SAMLProcessingFilter.class, ssoFilter);

        if(Optional.ofNullable(enableSsoHoK).orElseGet(config::isEnableSsoHoK)) {
            SAMLWebSSOHoKProcessingFilter ssoHoKFilter = new SAMLWebSSOHoKProcessingFilter();
            ssoHoKFilter.setAuthenticationSuccessHandler(successHandler);
            ssoHoKFilter.setAuthenticationManager(authenticationManager);
            ssoHoKFilter.setAuthenticationFailureHandler(failureHandler);
            builder.setSharedObject(SAMLWebSSOHoKProcessingFilter.class, ssoHoKFilter);
        }

        SAMLDiscovery discoveryFilter = new SAMLDiscovery();
        discoveryProcessingURL = Optional.ofNullable(discoveryProcessingURL).orElseGet(config::getDiscoveryProcessingURL);
        endpoints.setDiscoveryProcessingURL(discoveryProcessingURL);
        discoveryFilter.setFilterProcessesUrl(discoveryProcessingURL);
        idpSelectionPageURL = Optional.ofNullable(idpSelectionPageURL).orElseGet(config::getIdpSelectionPageURL);
        endpoints.setIdpSelectionPageURL(idpSelectionPageURL);
        discoveryFilter.setIdpSelectionPath(idpSelectionPageURL);
        builder.setSharedObject(SAMLDiscovery.class, discoveryFilter);

        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
        entryPoint.setDefaultProfileOptions(Optional.ofNullable(profileOptions).orElseGet(config::getProfileOptions));
        ssoLoginURL = Optional.ofNullable(ssoLoginURL).orElseGet(config::getSsoLoginURL);
        endpoints.setSsoLoginURL(ssoLoginURL);
        entryPoint.setFilterProcessesUrl(ssoLoginURL);
        builder.setSharedObject(SAMLEntryPoint.class, entryPoint);
    }

    public SSOConfigurer defaultSuccessURL(String defaultSuccessURL) {
        this.defaultSuccessURL = defaultSuccessURL;
        return this;
    }

    public SSOConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public SSOConfigurer defaultFailureURL(String defaultFailureURL) {
        this.defaultFailureURL = defaultFailureURL;
        return this;
    }

    public SSOConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public SSOConfigurer ssoProcessingURL(String ssoProcessingURL) {
        this.ssoProcessingURL = ssoProcessingURL;
        return this;
    }

    public SSOConfigurer enableSsoHoK(boolean enableSsoHoK) {
        this.enableSsoHoK = enableSsoHoK;
        return this;
    }

    public SSOConfigurer discoveryProcessingURL(String discoveryProcessingURL) {
        this.discoveryProcessingURL = discoveryProcessingURL;
        return this;
    }

    public SSOConfigurer idpSelectionPageURL(String idpSelectionPageURL) {
        this.idpSelectionPageURL = idpSelectionPageURL;
        return this;
    }

    public SSOConfigurer ssoLoginURL(String ssoLoginURL) {
        this.ssoLoginURL = ssoLoginURL;
        return this;
    }

    public SSOConfigurer profileOptions(WebSSOProfileOptions profileOptions) {
        this.profileOptions = profileOptions;
        return this;
    }
}
