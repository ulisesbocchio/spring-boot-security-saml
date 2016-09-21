package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils;
import com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.CheckedConsumer;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;
import java.util.function.Consumer;

/**
 * @author Ulises Bocchio
 */
@Data
@AllArgsConstructor
public class ServiceProviderBuilderResult {

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
    private CheckedConsumer<HttpSecurity, Exception> httpSecurityConsumer;
}
