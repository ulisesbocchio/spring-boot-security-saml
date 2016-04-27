package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.user.SimpleSAMLUserDetailsService;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * Configures Authentication Provider
 */
public class AuthenticationProviderConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private Boolean excludeCredential = null;
    private Boolean forcePrincipalAsString = null;
    private SAMLUserDetailsService userDetailsService;
    private SAMLAuthenticationProvider authenticationProvider;
    private SAMLSsoProperties config;

    public AuthenticationProviderConfigurer(SAMLAuthenticationProvider provider) {
        authenticationProvider = provider;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSsoProperties.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if(excludeCredential == null) {
            excludeCredential = config.getAuthenticationProvider().isExcludeCredential();
        }
        authenticationProvider.setExcludeCredential(excludeCredential);

        if(forcePrincipalAsString == null) {
            forcePrincipalAsString = config.getAuthenticationProvider().isForcePrincipalAsString();
        }
        authenticationProvider.setForcePrincipalAsString(forcePrincipalAsString);

        if(userDetailsService == null) {
            userDetailsService = new SimpleSAMLUserDetailsService();
        }
        authenticationProvider.setUserDetails(postProcess(userDetailsService));

        builder.setSharedObject(SAMLAuthenticationProvider.class, authenticationProvider);
    }

    public AuthenticationProviderConfigurer excludeCredential(boolean excludeCredential) {
        getBuilder().getSharedObject(SAMLAuthenticationProvider.class).setExcludeCredential(excludeCredential);
        return this;
    }

    public AuthenticationProviderConfigurer forcePrincipalAsString(boolean forcePrincipalAsString) {
        getBuilder().getSharedObject(SAMLAuthenticationProvider.class).setForcePrincipalAsString(forcePrincipalAsString);
        return this;
    }

    public AuthenticationProviderConfigurer userDetailsService(SAMLUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        return this;
    }
}
