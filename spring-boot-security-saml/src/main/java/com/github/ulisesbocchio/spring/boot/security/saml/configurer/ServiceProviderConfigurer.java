package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * @author Ulises Bocchio
 */
public interface ServiceProviderConfigurer {

    void configure(ServiceProviderSecurityConfigurer resources) throws Exception;

    void configure(HttpSecurity http) throws Exception;
}
