package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.Saml2SsoProperties;
import lombok.SneakyThrows;
import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.web.DefaultSecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer>{

    private List<MetadataProvider> metadataProviders = new ArrayList<>();

    public ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    @Override
    protected ServiceProviderSecurityConfigurer performBuild() throws Exception {
        MetadataManager metadataManager = getSharedObject(MetadataManager.class);
        if(metadataManager == null) {
            metadataManager = new CachingMetadataManager(metadataProviders);
        } else {
            metadataManager.setProviders(metadataProviders);
        }
        return new ServiceProviderSecurityConfigurer(metadataManager);
    }

    public MetadataManagerConfigurer metadataManager(MetadataManager metadataManager) throws Exception {
        metadataProviders.addAll(metadataManager.getProviders());
        setSharedObject(MetadataManager.class, metadataManager);
        return getOrApply(new MetadataManagerConfigurer(this));
    }

    public MetadataManagerConfigurer metadataManager() throws Exception {
        setSharedObject(MetadataManager.class, new CachingMetadataManager(metadataProviders));
        return getOrApply(new MetadataManagerConfigurer(this));
    }

    private <C extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>> C getOrApply(
            C configurer) throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }

    protected void setMetadataProviders(List<ExtendedMetadataDelegate> metadataProviders) {
        this.metadataProviders.addAll(metadataProviders);
    }

    public static class MetadataManagerConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

        private final ServiceProviderSecurityBuilder serviceProviderBuilder;
        List<MetadataProvider> metadataProviders = new ArrayList<>();
        private MetadataFilter metadataFilter = null;

        public MetadataManagerConfigurer(ServiceProviderSecurityBuilder serviceProviderSecurityBuilder) {
            this.serviceProviderBuilder = serviceProviderSecurityBuilder;
        }

        @Override
        public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
            List<ExtendedMetadataDelegate> extendedMetadataDelegates = metadataProviders.stream()
                .map(this::setParserPool)
                .map(this::getExtendedProvider)
                .collect(Collectors.toList());
            serviceProviderBuilder.setMetadataProviders(extendedMetadataDelegates);
        }

        private MetadataProvider setParserPool(MetadataProvider provider) {
            if(provider instanceof AbstractMetadataProvider) {
                ((AbstractMetadataProvider) provider).setParserPool(getBuilder().getSharedObject(ParserPool.class));
            }
            return provider;
        }

        @SneakyThrows
        private ExtendedMetadataDelegate getExtendedProvider(MetadataProvider provider) {
            if(provider instanceof ExtendedMetadataDelegate) {
                return (ExtendedMetadataDelegate) provider;
            }
            ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, getBuilder().getSharedObject(ExtendedMetadata.class));
            Saml2SsoProperties.ExtendedMetadataDelegateConfiguration extendedDelegate = getBuilder().getSharedObject(Saml2SsoProperties.class).getExtendedDelegate();
            extendedMetadataDelegate.setForceMetadataRevocationCheck(extendedDelegate.isForceMetadataRevocationCheck());
            extendedMetadataDelegate.setMetadataRequireSignature(extendedDelegate.isMetadataRequireSignature());
            extendedMetadataDelegate.setMetadataTrustCheck(extendedDelegate.isMetadataTrustCheck());
            extendedMetadataDelegate.setMetadataTrustedKeys(extendedDelegate.getMetadataTrustedKeys());
            extendedMetadataDelegate.setMetadataFilter(metadataFilter);
            extendedMetadataDelegate.setRequireValidMetadata(extendedDelegate.isRequireValidMetadata());
            return extendedMetadataDelegate;
        }

        public MetadataManagerConfigurer metadataProvider(MetadataProvider provider) {
            metadataProviders.add(provider);
            return this;
        }

        public ServiceProviderSecurityBuilder metadataProviders(MetadataProvider... providers) {
            metadataProviders = Arrays.asList(providers);
            return getBuilder();
        }

        public ServiceProviderSecurityBuilder metadataProviders(List<MetadataProvider> providers) {
            metadataProviders = new ArrayList<>(providers);
            return getBuilder();
        }

        public MetadataManagerConfigurer metadataFilter(MetadataFilter filter) {
            metadataFilter = filter;
            return this;
        }

    }

}
