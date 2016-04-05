package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends
        SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
}
