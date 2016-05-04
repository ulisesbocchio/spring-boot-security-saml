package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;

/**
 * @author Ulises Bocchio
 */
public class SAMLContextProviderConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private SAMLContextProvider samlContextProvider;
    private SAMLContextProvider samlContextProviderBean;

    public SAMLContextProviderConfigurer(SAMLContextProvider samlContextProvider) {

        this.samlContextProvider = samlContextProvider;
    }

    public SAMLContextProviderConfigurer() {

    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        samlContextProviderBean = builder.getSharedObject(SAMLContextProvider.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (samlContextProviderBean == null) {
            if (samlContextProvider == null) {
                samlContextProvider = new SAMLContextProviderImpl();
            }
            builder.setSharedObject(SAMLContextProvider.class, samlContextProvider);
        }
    }
}
