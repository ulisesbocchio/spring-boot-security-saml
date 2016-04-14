package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * @author Ulises Bocchio
 */
@Configuration
public class SAML2ServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

    private List<ServiceProviderConfigurer> serviceProviderConfigurers = Collections.emptyList();

    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ServiceProviderSecurityBuilder securityConfigurer = new ServiceProviderSecurityBuilder();
        serviceProviderConfigurers.stream().forEach(propagate(c -> c.configure(http)));
        serviceProviderConfigurers.stream().forEach(propagate(c -> c.configure(securityConfigurer)));
        http.apply(securityConfigurer.build());
    }

    @Autowired(required = false)
    public void setServiceProviderConfigurers(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        this.serviceProviderConfigurers = serviceProviderConfigurers;
    }

    private <T, E extends Throwable> Consumer<T> propagate(UnsafeConsumer<T, E> consumer) {
        return t -> {
            try {
                consumer.accept(t);
            } catch (Throwable e) {
                throw e instanceof RuntimeException ? (RuntimeException) e : new RuntimeException(e);
            }
        };
    }

    @FunctionalInterface
    private interface UnsafeConsumer<T, E extends Throwable> {
        void accept(T t) throws E;
    }
}
