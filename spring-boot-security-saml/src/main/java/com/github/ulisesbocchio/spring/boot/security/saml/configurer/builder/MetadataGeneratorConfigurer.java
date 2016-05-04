package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

/**
 * Configures metadata generator filter for SAML Service Provider
 */
public class MetadataGeneratorConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String metadataURL;
    private String entityId;
    private Boolean wantAssertionSigned;
    private Boolean requestSigned;
    private Collection<String> nameId;
    private String entityBaseURL;
    private Collection<String> bindingsHoKSSO;
    private Collection<String> bindingsSLO;
    private Collection<String> bindingsSSO;
    private Integer assertionConsumerIndex;
    private Boolean includeDiscoveryExtension;
    private SAMLSsoProperties.MetadataGeneratorConfiguration config;
    private ServiceProviderEndpoints endpoints;
    private ExtendedMetadata extendedMetadata;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSsoProperties.class).getMetadataGenerator();
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
        extendedMetadata = builder.getSharedObject(ExtendedMetadata.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
        metadataURL = Optional.ofNullable(metadataURL).orElseGet(config::getMetadataURL);
        endpoints.setMetadataURL(metadataURL);
        metadataDisplayFilter.setFilterProcessesUrl(metadataURL);

        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(Optional.ofNullable(entityId).orElseGet(config::getEntityId));
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        metadataGenerator.setWantAssertionSigned(Optional.ofNullable(wantAssertionSigned).orElseGet(config::isWantAssertionSigned));
        metadataGenerator.setRequestSigned(Optional.ofNullable(requestSigned).orElseGet(config::isRequestSigned));
        metadataGenerator.setNameID(Optional.ofNullable(nameId).orElseGet(config::getNameId));
        metadataGenerator.setEntityBaseURL(Optional.ofNullable(entityBaseURL).orElseGet(config::getEntityBaseURL));
        metadataGenerator.setBindingsHoKSSO(Optional.ofNullable(bindingsHoKSSO).orElseGet(config::getBindingsHoKSSO));
        metadataGenerator.setBindingsSLO(Optional.ofNullable(bindingsSLO).orElseGet(config::getBindingsSLO));
        metadataGenerator.setBindingsSSO(Optional.ofNullable(bindingsSSO).orElseGet(config::getBindingsSSO));
        metadataGenerator.setAssertionConsumerIndex(Optional.ofNullable(assertionConsumerIndex).orElseGet(config::getAssertionConsumerIndex));
        metadataGenerator.setIncludeDiscoveryExtension(Optional.ofNullable(includeDiscoveryExtension).orElseGet(config::isIncludeDiscoveryExtension));

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(metadataGenerator);

        builder.setSharedObject(MetadataGenerator.class, metadataGenerator);
        builder.setSharedObject(MetadataDisplayFilter.class, metadataDisplayFilter);
        builder.setSharedObject(MetadataGeneratorFilter.class, metadataGeneratorFilter);
    }

    public MetadataGeneratorConfigurer metadataURL(String metadataURL) {
        this.metadataURL = metadataURL;
        return this;
    }

    public MetadataGeneratorConfigurer entityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public MetadataGeneratorConfigurer wantAssertionSigned(Boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
        return this;
    }

    public MetadataGeneratorConfigurer requestSigned(Boolean requestSigned) {
        this.requestSigned = requestSigned;
        return this;
    }

    public MetadataGeneratorConfigurer nameId(String... nameId) {
        this.nameId = Arrays.asList(nameId);
        return this;
    }

    public MetadataGeneratorConfigurer entityBaseURL(String entityBaseURL) {
        this.entityBaseURL = entityBaseURL;
        return this;
    }

    public MetadataGeneratorConfigurer bindingsHoKSSO(String... bindingsHoKSSO) {
        this.bindingsHoKSSO = Arrays.asList(bindingsHoKSSO);
        return this;
    }

    public MetadataGeneratorConfigurer bindingsSLO(String... bindingsSLO) {
        this.bindingsSLO = Arrays.asList(bindingsSLO);
        return this;
    }

    public MetadataGeneratorConfigurer bindingsSSO(String... bindingsSSO) {
        this.bindingsSSO = Arrays.asList(bindingsSSO);
        return this;
    }

    public MetadataGeneratorConfigurer assertionConsumerIndex(Integer assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
        return this;
    }

    public MetadataGeneratorConfigurer includeDiscoveryExtension(Boolean includeDiscoveryExtension) {
        this.includeDiscoveryExtension = includeDiscoveryExtension;
        return this;
    }
}
