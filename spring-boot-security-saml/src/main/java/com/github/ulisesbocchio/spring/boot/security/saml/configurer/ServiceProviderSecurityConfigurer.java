package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private SAMLSsoProperties config;
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
    private TLSProtocolConfigurer tlsProtocolConfigurer;

    public ServiceProviderSecurityConfigurer(SAMLSsoProperties config, MetadataManager metadataManager, SAMLAuthenticationProvider authenticationProvider,
                                             SAMLProcessor samlProcessor, SAMLLogoutFilter samlLogoutFilter, SAMLLogoutProcessingFilter samlLogoutProcessingFilter,
                                             MetadataDisplayFilter metadataDisplayFilter, MetadataGeneratorFilter metadataGeneratorFilter,
                                             SAMLProcessingFilter sAMLProcessingFilter, SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter,
                                             SAMLDiscovery sAMLDiscovery, SAMLEntryPoint sAMLEntryPoint, KeyManager keyManager, TLSProtocolConfigurer tlsProtocolConfigurer) {
        this.config = config;
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
        this.tlsProtocolConfigurer = tlsProtocolConfigurer;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
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
        postProcess(tlsProtocolConfigurer);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .httpBasic()
            .disable();
        http
            .csrf()
            .disable();
        http
            .addFilterAfter(metadataGeneratorFilter, BasicAuthenticationFilter.class)
            .addFilterAfter(metadataDisplayFilter, MetadataGeneratorFilter.class)
            .addFilterAfter(sAMLEntryPoint, MetadataDisplayFilter.class)
            .addFilterAfter(sAMLProcessingFilter, SAMLEntryPoint.class)
            .addFilterAfter(sAMLWebSSOHoKProcessingFilter, SAMLProcessingFilter.class)
            .addFilterAfter(samlLogoutProcessingFilter, SAMLWebSSOHoKProcessingFilter.class)
            .addFilterAfter(sAMLDiscovery, SAMLLogoutProcessingFilter.class)
            .addFilterAfter(samlLogoutFilter, LogoutFilter.class);
        http
            .authorizeRequests()
            .antMatchers("/error", "/saml/**", "/idpselection").permitAll()
            .anyRequest().authenticated();
        http
            .exceptionHandling()
            .authenticationEntryPoint(sAMLEntryPoint);
        http
            .logout()
            .disable();
    }
}
