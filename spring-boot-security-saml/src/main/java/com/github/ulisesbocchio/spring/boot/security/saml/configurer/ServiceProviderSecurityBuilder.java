package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.web.DefaultSecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer>{

    protected ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    @Override
    protected ServiceProviderSecurityConfigurer performBuild() throws Exception {
        return new ServiceProviderSecurityConfigurer();
    }

    public ServiceProviderSecurityBuilder metadataManager(MetadataManager metadataManager) {
        setSharedObject(MetadataManager.class, metadataManager);
        return this;
    }

    public MetadataManagerConfigurer metadataManager() throws Exception {
        return getOrApply(new MetadataManagerConfigurer());
    }

    private <C extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>> C getOrApply(
            C configurer) throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }

    public static class MetadataManagerConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

        List<MetadataProvider> metadataProviders = new ArrayList<>();

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
            super.init(builder);
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            super.configure(builder);
        }

        public MetadataManagerConfigurer metadataProvider(MetadataProvider provider) {
            metadataProviders.add(provider);
            return this;
        }

        public ServiceProviderSecurityBuilder metadataProviders(MetadataProvider... providers) {
            metadataProviders = Arrays.asList(providers);
            return getBuilder();
        }
    }

}
