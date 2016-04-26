package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private MetadataManager metadataManager;
    private SAMLAuthenticationProvider authenticationProvider;
    private SAMLProcessor samlProcessor;
    private SAMLLogoutFilter samlLogoutFilter;
    private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;
    private MetadataDisplayFilter metadataDisplayFilter;
    private MetadataGeneratorFilter metadataGeneratorFilter;
    private SAMLProcessingFilter sAMLProcessingFilter;
    private SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter;
    private SAMLDiscovery sAMLDiscovery;
    private SAMLEntryPoint sAMLEntryPoint;
    private KeyManager keyManager;

    public ServiceProviderSecurityConfigurer(MetadataManager metadataManager, SAMLAuthenticationProvider authenticationProvider, SAMLProcessor samlProcessor,
                                             SAMLLogoutFilter samlLogoutFilter, SAMLLogoutProcessingFilter samlLogoutProcessingFilter,
                                             MetadataDisplayFilter metadataDisplayFilter, MetadataGeneratorFilter metadataGeneratorFilter,
                                             SAMLProcessingFilter sAMLProcessingFilter, SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter,
                                             SAMLDiscovery sAMLDiscovery, SAMLEntryPoint sAMLEntryPoint, KeyManager keyManager) {
        this.metadataManager = metadataManager;
        this.authenticationProvider = authenticationProvider;
        this.samlProcessor = samlProcessor;
        this.samlLogoutFilter = samlLogoutFilter;
        this.samlLogoutProcessingFilter = samlLogoutProcessingFilter;
        this.metadataDisplayFilter = metadataDisplayFilter;
        this.metadataGeneratorFilter = metadataGeneratorFilter;
        this.sAMLProcessingFilter = sAMLProcessingFilter;
        this.sAMLWebSSOHoKProcessingFilter = sAMLWebSSOHoKProcessingFilter;
        this.sAMLDiscovery = sAMLDiscovery;
        this.sAMLEntryPoint = sAMLEntryPoint;
        this.keyManager = keyManager;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        postProcess(metadataManager);
        postProcess(authenticationProvider);
        postProcess(samlProcessor);
        postProcess(samlLogoutFilter);
        postProcess(samlLogoutProcessingFilter);
        postProcess(metadataDisplayFilter);
        postProcess(metadataGeneratorFilter);
        postProcess(sAMLProcessingFilter);
        postProcess(sAMLWebSSOHoKProcessingFilter);
        postProcess(sAMLDiscovery);
        postProcess(sAMLEntryPoint);
        postProcess(keyManager);
    }
}
