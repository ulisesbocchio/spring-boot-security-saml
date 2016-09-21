package com.github.ulisesbocchio.spring.boot.security.saml.bean;

import com.github.ulisesbocchio.spring.boot.security.saml.configuration.SAMLServiceProviderSecurityConfiguration.ServiceProviderBuilderHolder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilderResult;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.CheckedConsumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
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
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * @author Ulises Bocchio
 */
public class SAMLConfigurerBean extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

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
    private CheckedConsumer<HttpSecurity, Exception> httpConsumer;

    @Autowired
    private ServiceProviderBuilderHolder builderHolder;
    @Autowired
    private AuthenticationManager authenticationManager;

    public SAMLConfigurerBean() {
    }

    public SAMLConfigurerBean(ServiceProviderBuilderHolder builderHolder, AuthenticationManager authenticationManager) {
        this.builderHolder = builderHolder;
        this.authenticationManager = authenticationManager;
    }

    public ServiceProviderBuilder serviceProvider() {
        return builderHolder.getBuilder();
    }

    public ServiceProviderBuilder serviceProvider(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        serviceProviderConfigurers.forEach(unchecked(spc -> spc.configure(serviceProvider())));
        return serviceProvider();
    }

    private ServiceProviderEndpoints endpoints() {
        return Optional.ofNullable(builderHolder)
                .map(ServiceProviderBuilderHolder::getBuilder)
                .map(builder -> builder.getSharedObject(ServiceProviderEndpoints.class))
                .orElseThrow(() -> new IllegalStateException("Can't find SAML Endpoints"));
    }

    public RequestMatcher endpointsMatcher() {
        return new LazyEndpointsRequestMatcher(endpoints());
    }

    private static class LazyEndpointsRequestMatcher implements RequestMatcher {

        private RequestMatcher delegate;
        private final ServiceProviderEndpoints endpoints;

        private LazyEndpointsRequestMatcher(ServiceProviderEndpoints endpoints) {
            this.endpoints = endpoints;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            if(delegate == null) {
                synchronized (this) {
                    if(delegate == null) {
                        delegate = endpoints.getRequestMatcher();
                    }
                }
            }
            return delegate.matches(request);
        }
    }

    @Override
    public void setBuilder(HttpSecurity httpSecurity) {
        builderHolder.getBuilder().setSharedObject(HttpSecurity.class, httpSecurity);
        super.setBuilder(httpSecurity);
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        builderHolder.getBuilder().setSharedObject(AuthenticationManager.class, authenticationManager);
        setFields(builderHolder.getBuilder().build());
        // @formatter:off
        http
            .exceptionHandling()
            .authenticationEntryPoint(sAMLEntryPoint);
        http
            .logout()
            .disable();
        http.
            authenticationProvider(authenticationProvider);

        if(httpConsumer != null) {
            httpConsumer.accept(http);
        }
        // @formatter:on
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        //http
        addFilterAfter(http, metadataGeneratorFilter);
        addFilterAfter(http, metadataDisplayFilter);
        addFilterAfter(http, sAMLEntryPoint);
        addFilterAfter(http, sAMLProcessingFilter);
        addFilterAfter(http, sAMLWebSSOHoKProcessingFilter);
        addFilterAfter(http, samlLogoutProcessingFilter);
        addFilterAfter(http, sAMLDiscovery);
        addFilterAfter(http, samlLogoutFilter);
        // @formatter:on
    }

    private void addFilterAfter(HttpSecurity http, Filter filterBeingAdded) {
        if (filterBeingAdded != null) {
            http.addFilterAfter(filterBeingAdded, lastFilterClass);
            lastFilterClass = filterBeingAdded.getClass();
        }
    }

    public void setFields(ServiceProviderBuilderResult beans) {
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
        this.httpConsumer = beans.getHttpSecurityConsumer();
    }
}
