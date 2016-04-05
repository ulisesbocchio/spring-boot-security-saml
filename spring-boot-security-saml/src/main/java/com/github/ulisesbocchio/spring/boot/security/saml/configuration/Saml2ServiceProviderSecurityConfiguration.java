package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author Ulises Bocchio
 */
@Configuration
public class Saml2ServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

    @Override
    public int getOrder() {
        return 1;
    }
}
