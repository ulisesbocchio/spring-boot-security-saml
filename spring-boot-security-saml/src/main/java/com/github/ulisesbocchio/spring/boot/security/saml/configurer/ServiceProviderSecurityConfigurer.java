package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.beans.factory.InitializingBean;
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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;

/**
 * Class for internal usage of this Spring Boot Plugin. This configurer wires Spring Security's {@link HttpSecurity}
 * builder with the results of {@link ServiceProviderSecurityBuilder}. Once all the configuration has been executed by
 * the Service Provider Builder, all that's left is to wire a Spring Security's Filter Chain with all the different
 * filters applicable for the desired configuration, and the Authentication Provider. Prior to that, all beans are
 * postProcessed and all
 * {@link InitializingBean} implementors are called.
 *
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private SAMLSSOProperties config;
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
    private ServiceProviderEndpoints endpoints;
    private Class<? extends Filter> lastFilterClass = BasicAuthenticationFilter.class;

    public ServiceProviderSecurityConfigurer(SAMLSSOProperties config, MetadataManager metadataManager, SAMLAuthenticationProvider authenticationProvider,
                                             SAMLProcessor samlProcessor, SAMLLogoutFilter samlLogoutFilter, SAMLLogoutProcessingFilter samlLogoutProcessingFilter,
                                             MetadataDisplayFilter metadataDisplayFilter, MetadataGeneratorFilter metadataGeneratorFilter,
                                             SAMLProcessingFilter sAMLProcessingFilter, SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter,
                                             SAMLDiscovery sAMLDiscovery, SAMLEntryPoint sAMLEntryPoint, KeyManager keyManager, TLSProtocolConfigurer tlsProtocolConfigurer,
                                             ServiceProviderEndpoints endpoints) {
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
        this.endpoints = endpoints;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        metadataManager.setRefreshRequired(true);
        postProcess(metadataManager);
        postProcess(authenticationProvider);
        postProcess(samlProcessor);
        postProcess(samlLogoutFilter);
        postProcess(samlLogoutProcessingFilter);
        postProcess(metadataDisplayFilter);
        postProcess(metadataGeneratorFilter);
        postProcess(sAMLProcessingFilter);
        if (sAMLWebSSOHoKProcessingFilter != null) {
            postProcess(sAMLWebSSOHoKProcessingFilter);
        }
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
        //http
        addFilterAfter(http, metadataGeneratorFilter);
        addFilterAfter(http, metadataDisplayFilter);
        addFilterAfter(http, sAMLEntryPoint);
        addFilterAfter(http, sAMLProcessingFilter);
        addFilterAfter(http, sAMLWebSSOHoKProcessingFilter);
        addFilterAfter(http, samlLogoutProcessingFilter);
        addFilterAfter(http, sAMLDiscovery);
        addFilterAfter(http, samlLogoutFilter);
        http
                .authorizeRequests()
                .requestMatchers(endpoints.getRequestMatcher()).permitAll()
                .anyRequest().authenticated();
        http
                .exceptionHandling()
                .authenticationEntryPoint(sAMLEntryPoint);
        http
                .logout()
                .disable();
        http.
                authenticationProvider(authenticationProvider);
    }

    private void addFilterAfter(HttpSecurity http, Filter filterBeingAdded) {
        if (filterBeingAdded != null) {
            http.addFilterAfter(filterBeingAdded, lastFilterClass);
            lastFilterClass = filterBeingAdded.getClass();
        }
    }
}
