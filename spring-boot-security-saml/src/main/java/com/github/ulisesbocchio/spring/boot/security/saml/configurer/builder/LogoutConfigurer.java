package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.util.Optional;

/**
 * Configures the Logout aspect of the SAML Service Provider
 */
public class LogoutConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {
    private String defaultTargetURL;
    private String logoutURL;
    private String singleLogoutURL;
    private Boolean clearAuthentication;
    private Boolean invalidateSession;
    private LogoutSuccessHandler successHandler;
    private LogoutHandler localHandler;
    private LogoutHandler globalHandler;
    private SAMLSsoProperties.LogoutConfiguration config;
    private ServiceProviderEndpoints endpoints;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSsoProperties.class).getLogout();
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if(successHandler == null) {
            SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
            defaultTargetURL = Optional.ofNullable(defaultTargetURL).orElseGet(config::getDefaultTargetURL);
            successLogoutHandler.setDefaultTargetUrl(defaultTargetURL);
            endpoints.setDefaultTargetURL(defaultTargetURL);
            successHandler = postProcess(successLogoutHandler);
        }

        if(localHandler == null) {
            SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
            logoutHandler.setInvalidateHttpSession(Optional.ofNullable(invalidateSession).orElseGet(config::isInvalidateSession));
            logoutHandler.setClearAuthentication(Optional.ofNullable(clearAuthentication).orElseGet(config::isClearAuthentication));
            localHandler = postProcess(logoutHandler);
        }

        if(globalHandler == null) {
            globalHandler = localHandler;
        }

        SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(successHandler, new LogoutHandler[]{localHandler}, new LogoutHandler[]{globalHandler});
        logoutURL = Optional.ofNullable(logoutURL).orElseGet(config::getLogoutURL);
        endpoints.setLogoutURL(logoutURL);
        samlLogoutFilter.setFilterProcessesUrl(logoutURL);

        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(successHandler, globalHandler);
        singleLogoutURL = Optional.ofNullable(singleLogoutURL).orElseGet(config::getSingleLogoutURL);
        samlLogoutProcessingFilter.setFilterProcessesUrl(singleLogoutURL);
        endpoints.setSingleLogoutURL(singleLogoutURL);

        builder.setSharedObject(SAMLLogoutFilter.class, samlLogoutFilter);
        builder.setSharedObject(SAMLLogoutProcessingFilter.class, samlLogoutProcessingFilter);
    }

    public LogoutConfigurer defaultTargetURL(String url) {
        defaultTargetURL = url;
        return this;
    }

    public LogoutConfigurer logoutURL(String url) {
        logoutURL = url;
        return this;
    }

    public LogoutConfigurer singleLogoutURL(String url) {
        singleLogoutURL = url;
        return this;
    }

    public LogoutConfigurer clearAuthentication(Boolean value) {
        clearAuthentication = value;
        return this;
    }

    public LogoutConfigurer invalidateSession(Boolean value) {
        invalidateSession = value;
        return this;
    }

    public LogoutConfigurer successHandler(LogoutSuccessHandler handler) {
        successHandler = handler;
        return this;
    }

    public LogoutConfigurer localHandler(LogoutHandler handler) {
        localHandler = handler;
        return this;
    }

    public LogoutConfigurer globalHandler(LogoutHandler handler) {
        globalHandler = handler;
        return this;
    }
}
