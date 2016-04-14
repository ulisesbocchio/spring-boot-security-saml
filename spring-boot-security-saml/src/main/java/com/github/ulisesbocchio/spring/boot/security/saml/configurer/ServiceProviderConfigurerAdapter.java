package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderConfigurerAdapter implements ServiceProviderConfigurer {
    @Override
    public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
    }
}
