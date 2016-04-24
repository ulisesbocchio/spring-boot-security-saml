package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private MetadataManager metadataManager;
    private SAMLAuthenticationProvider authenticationProvider;
    private SAMLProcessor samlProcessor;

    public ServiceProviderSecurityConfigurer(MetadataManager metadataManager, SAMLAuthenticationProvider authenticationProvider, SAMLProcessor samlProcessor) {
        this.metadataManager = metadataManager;
        this.authenticationProvider = authenticationProvider;
        this.samlProcessor = samlProcessor;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        postProcess(metadataManager);
        postProcess(authenticationProvider);
        postProcess(samlProcessor);
    }
}
