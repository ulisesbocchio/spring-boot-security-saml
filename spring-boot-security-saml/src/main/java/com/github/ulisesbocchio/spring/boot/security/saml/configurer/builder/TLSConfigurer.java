package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;

import java.util.Optional;
import java.util.Set;

/**
 * Configures Single Sign On filter for SAML Service Provider
 */
public class TLSConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String protocolName;
    private Integer protocolPort;
    private String sslHostnameVerification;
    private Set<String> trustedKeys;
    private SAMLSSOProperties.TLSConfiguration config;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getTls();
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
        configurer.setProtocolName(Optional.ofNullable(protocolName).orElseGet(config::getProtocolName));
        configurer.setProtocolPort(Optional.ofNullable(protocolPort).orElseGet(config::getProtocolPort));
        configurer.setSslHostnameVerification(Optional.ofNullable(sslHostnameVerification).orElseGet(config::getSslHostnameVerification));
        configurer.setTrustedKeys(Optional.ofNullable(trustedKeys).orElseGet(config::getTrustedKeys));
        builder.setSharedObject(TLSProtocolConfigurer.class, configurer);
    }

    public TLSConfigurer protocolName(String protocolName) {
        this.protocolName = protocolName;
        return this;
    }

    public TLSConfigurer protocolPort(int protocolPort) {
        this.protocolPort = protocolPort;
        return this;
    }

    public TLSConfigurer sslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
        return this;
    }

    public TLSConfigurer trustedKeys(Set<String> trustedKeys) {
        this.trustedKeys = trustedKeys;
        return this;
    }
}
