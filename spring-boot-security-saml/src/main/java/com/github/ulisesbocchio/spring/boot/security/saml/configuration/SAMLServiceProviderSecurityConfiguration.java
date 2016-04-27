package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;

import java.util.Collections;
import java.util.List;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * @author Ulises Bocchio
 */
@Configuration
@EnableConfigurationProperties(SAMLSsoProperties.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SAMLServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private List<ServiceProviderConfigurer> serviceProviderConfigurers = Collections.emptyList();

    @Autowired
    private ObjectPostProcessor<Object> objectPostProcessor;

    @Autowired
    private SAMLSsoProperties sAMLSsoProperties;

    @Autowired(required = false)
    private ExtendedMetadata extendedMetadata;

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    private CachingMetadataManager metadataManager;

    @Autowired
    @Qualifier("webSSOprofileConsumer")
    private WebSSOProfileConsumer webSSOProfileConsumer;

    @Autowired
    @Qualifier("hokWebSSOprofileConsumer")
    WebSSOProfileConsumerHoKImpl hokWebSSOProfileConsumer;

    @Autowired
    AutowireCapableBeanFactory beanFactory;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ServiceProviderSecurityBuilder securityConfigurer = new ServiceProviderSecurityBuilder(beanFactory);
        securityConfigurer.setSharedObject(ParserPool.class, ParserPoolHolder.getPool());
        securityConfigurer.setSharedObject(MetadataManager.class, metadataManager);
        securityConfigurer.setSharedObject(WebSSOProfileConsumerImpl.class, (WebSSOProfileConsumerImpl) webSSOProfileConsumer);
        securityConfigurer.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);
        securityConfigurer.setSharedObject(ServiceProviderEndpoints.class, new ServiceProviderEndpoints());
        securityConfigurer.setSharedObject(ResourceLoader.class, resourceLoader);
        securityConfigurer.setSharedObject(SAMLSsoProperties.class, sAMLSsoProperties);
        securityConfigurer.setSharedObject(ExtendedMetadata.class, extendedMetadata != null ? extendedMetadata : sAMLSsoProperties.getExtendedMetadata());
        securityConfigurer.setSharedObject(AuthenticationManager.class, authenticationManager());
        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(http)));
        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(securityConfigurer)));
        http.apply(securityConfigurer.build());
    }

    @Autowired(required = false)
    public void setServiceProviderConfigurers(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        this.serviceProviderConfigurers = serviceProviderConfigurers;
    }
}
