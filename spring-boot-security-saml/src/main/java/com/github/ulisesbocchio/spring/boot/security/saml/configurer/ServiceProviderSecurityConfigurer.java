package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

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

    private ServiceProviderSecurityBuilder securityConfigurerBuilder;
    private List<ServiceProviderConfigurer> serviceProviderConfigurers;


    public ServiceProviderSecurityConfigurer(ServiceProviderSecurityBuilder securityConfigurerBuilder, List<ServiceProviderConfigurer> serviceProviderConfigurers) {

        this.securityConfigurerBuilder = securityConfigurerBuilder;
        this.serviceProviderConfigurers = serviceProviderConfigurers;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        serviceProviderConfigurers.forEach(unchecked(spc -> spc.configure(securityConfigurerBuilder)));
        setFields(securityConfigurerBuilder.build());

        // @formatter:off
        http
            .httpBasic()
            .disable();
        http
            .csrf()
            .disable();
        http
            .exceptionHandling()
            .authenticationEntryPoint(sAMLEntryPoint);
        http
            .logout()
            .disable();
        http.
            authenticationProvider(authenticationProvider);

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
            .requestMatchers(endpoints.getRequestMatcher()).permitAll();

        serviceProviderConfigurers.forEach(unchecked(spc -> spc.configure(http)));

        http
            .authorizeRequests()
            .anyRequest()
            .authenticated();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

    }

    private void addFilterAfter(HttpSecurity http, Filter filterBeingAdded) {
        if (filterBeingAdded != null) {
            http.addFilterAfter(filterBeingAdded, lastFilterClass);
            lastFilterClass = filterBeingAdded.getClass();
        }
    }

    public void setFields(ServiceProviderSecurityConfigurerBeans beans) {
        this.config = beans.getConfig();
        this.metadataManager = beans.getMetadataManager();
        this.authenticationProvider = beans.getAuthenticationProvider();
        this.samlProcessor = beans.getSamlProcessor();
        this.samlLogoutFilter = beans.getSamlLogoutFilter();
        this.samlLogoutProcessingFilter = beans.getSamlLogoutProcessingFilter();
        this.metadataDisplayFilter = beans.getMetadataDisplayFilter();
        this.metadataGeneratorFilter = beans.getMetadataGeneratorFilter();
        this.sAMLProcessingFilter = beans.getSAMLProcessingFilter();
        this.sAMLWebSSOHoKProcessingFilter = beans.getSAMLWebSSOHoKProcessingFilter();
        this.sAMLDiscovery = beans.getSAMLDiscovery();
        this.sAMLEntryPoint = beans.getSAMLEntryPoint();
        this.keyManager = beans.getKeyManager();
        this.tlsProtocolConfigurer = beans.getTlsProtocolConfigurer();
        this.endpoints = beans.getEndpoints();
    }
}
