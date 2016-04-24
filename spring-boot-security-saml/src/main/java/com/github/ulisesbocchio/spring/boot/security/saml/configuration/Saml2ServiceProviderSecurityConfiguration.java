package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAML2SsoProperties;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.parser.ParserPoolHolder;

import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * @author Ulises Bocchio
 */
@Configuration
@EnableConfigurationProperties(SAML2SsoProperties.class)
public class SAML2ServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter implements Ordered {

    private List<ServiceProviderConfigurer> serviceProviderConfigurers = Collections.emptyList();

    @Autowired
    private ObjectPostProcessor<Object> objectPostProcessor;

    @Autowired
    private SAML2SsoProperties sAML2SsoProperties;

    @Autowired(required = false)
    private ExtendedMetadata extendedMetadata;

    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ServiceProviderSecurityBuilder securityConfigurer = new ServiceProviderSecurityBuilder(objectPostProcessor);
        securityConfigurer.setSharedObject(ParserPool.class, ParserPoolHolder.getPool());
        securityConfigurer.setSharedObject(SAML2SsoProperties.class, sAML2SsoProperties);
        securityConfigurer.setSharedObject(ExtendedMetadata.class, extendedMetadata != null ? extendedMetadata : sAML2SsoProperties.getExtendedMetadata());
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
