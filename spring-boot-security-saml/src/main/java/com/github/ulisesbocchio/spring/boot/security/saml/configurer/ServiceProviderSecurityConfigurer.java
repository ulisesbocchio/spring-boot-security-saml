package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private MetadataManager metadataManager;

    public ServiceProviderSecurityConfigurer(MetadataManager metadataManager) {
        this.metadataManager = metadataManager;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        postProcess(metadataManager);
    }
}
