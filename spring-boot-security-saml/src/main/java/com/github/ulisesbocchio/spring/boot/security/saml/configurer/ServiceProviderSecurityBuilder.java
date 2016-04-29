package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder.*;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;

import java.util.*;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer>{

    public ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    public ServiceProviderSecurityBuilder(AutowireCapableBeanFactory beanFactory) {
        super(new ObjectPostProcessor<Object>() {
            @Override
            public Object postProcess(Object object) {
                if(object != null) {
                    beanFactory.autowireBean(object);
                }
                return object;
            }
        });
    }

    @Override
    protected void beforeInit() throws Exception {
        authenticationProvider();
        metadataManager();
        logout();
        sso();
        keyManager();
        tls();
        metadataGenerator();
        sAMLProcessor();
    }

    @Override
    protected ServiceProviderSecurityConfigurer performBuild() throws Exception {
        SAMLSsoProperties config = getSharedObject(SAMLSsoProperties.class);

        MetadataManager metadataManager = getSharedObject(MetadataManager.class);

        WebSSOProfileConsumerImpl webSSOProfileConsumer = getSharedObject(WebSSOProfileConsumerImpl.class);
        WebSSOProfileConsumerHoKImpl hokWebSSOProfileConsumer = getSharedObject(WebSSOProfileConsumerHoKImpl.class);

        SAMLProcessor samlProcessor = getSharedObject(SAMLProcessor.class);
        postProcess(samlProcessor);
        webSSOProfileConsumer.setProcessor(samlProcessor);
        hokWebSSOProfileConsumer.setProcessor(samlProcessor);

        SAMLAuthenticationProvider authenticationProvider = getSharedObject(SAMLAuthenticationProvider.class);
        postProcess(authenticationProvider);

        SAMLLogoutFilter samlLogoutFilter = getSharedObject(SAMLLogoutFilter.class);
        postProcess(samlLogoutFilter);
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = getSharedObject(SAMLLogoutProcessingFilter.class);
        postProcess(samlLogoutProcessingFilter);

        MetadataDisplayFilter metadataDisplayFilter = getSharedObject(MetadataDisplayFilter.class);
        postProcess(metadataDisplayFilter);
        MetadataGeneratorFilter metadataGeneratorFilter = getSharedObject(MetadataGeneratorFilter.class);
        postProcess(metadataGeneratorFilter);
        MetadataGenerator metadataGenerator = getSharedObject(MetadataGenerator.class);

        SAMLProcessingFilter sAMLProcessingFilter = getSharedObject(SAMLProcessingFilter.class);
        postProcess(sAMLProcessingFilter);
        SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter = getSharedObject(SAMLWebSSOHoKProcessingFilter.class);
        postProcess(sAMLWebSSOHoKProcessingFilter);
        SAMLDiscovery sAMLDiscovery = getSharedObject(SAMLDiscovery.class);
        postProcess(sAMLDiscovery);
        SAMLEntryPoint sAMLEntryPoint = getSharedObject(SAMLEntryPoint.class);
        postProcess(sAMLEntryPoint);

        KeyManager keyManager = getSharedObject(KeyManager.class);
        postProcess(keyManager);
        metadataManager.setKeyManager(keyManager);
        metadataGenerator.setKeyManager(keyManager);

        TLSProtocolConfigurer tlsProtocolConfigurer = getSharedObject(TLSProtocolConfigurer.class);
        postProcess(tlsProtocolConfigurer);

        ServiceProviderEndpoints endpoints = getSharedObject(ServiceProviderEndpoints.class);

        return new ServiceProviderSecurityConfigurer(config, metadataManager, authenticationProvider, samlProcessor,
                samlLogoutFilter, samlLogoutProcessingFilter, metadataDisplayFilter, metadataGeneratorFilter,
                sAMLProcessingFilter, sAMLWebSSOHoKProcessingFilter, sAMLDiscovery, sAMLEntryPoint, keyManager,
                tlsProtocolConfigurer, endpoints);
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

    public AuthenticationProviderConfigurer authenticationProvider() throws Exception {
        return authenticationProvider(new SAMLAuthenticationProvider());
    }

    public AuthenticationProviderConfigurer authenticationProvider(SAMLAuthenticationProvider provider) throws Exception {
        return getOrApply(new AuthenticationProviderConfigurer(provider));
    }

    public SAMLProcessorConfigurer sAMLProcessor(SAMLProcessor sAMLProcessor) throws Exception {
        return getOrApply(new SAMLProcessorConfigurer(sAMLProcessor));
    }

    public SAMLProcessorConfigurer sAMLProcessor() throws Exception {
        return sAMLProcessor(null);
    }

    public LogoutConfigurer logout() throws Exception {
        return getOrApply(new LogoutConfigurer());
    }

    public MetadataGeneratorConfigurer metadataGenerator() throws Exception {
        return getOrApply(new MetadataGeneratorConfigurer());
    }

    public SSOConfigurer sso() throws Exception {
        return getOrApply(new SSOConfigurer());
    }

    public KeyManagerConfigurer keyManager() throws Exception {
        return keyManager(null);
    }

    public KeyManagerConfigurer keyManager(KeyManager keyManager) throws Exception {
        return getOrApply(new KeyManagerConfigurer(keyManager));
    }

    public TLSConfigurer tls() throws Exception {
        return getOrApply(new TLSConfigurer());
    }
}
