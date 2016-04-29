package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
        ServiceProviderSecurityBuilder securityConfigurerBuilder = new ServiceProviderSecurityBuilder(beanFactory);
        securityConfigurerBuilder.setSharedObject(ParserPool.class, ParserPoolHolder.getPool());
        securityConfigurerBuilder.setSharedObject(MetadataManager.class, metadataManager);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerImpl.class, (WebSSOProfileConsumerImpl) webSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(ServiceProviderEndpoints.class, new ServiceProviderEndpoints());
        securityConfigurerBuilder.setSharedObject(ResourceLoader.class, resourceLoader);
        securityConfigurerBuilder.setSharedObject(SAMLSsoProperties.class, sAMLSsoProperties);
        securityConfigurerBuilder.setSharedObject(ExtendedMetadata.class, extendedMetadata != null ? extendedMetadata : sAMLSsoProperties.getExtendedMetadata());
        securityConfigurerBuilder.setSharedObject(AuthenticationManager.class, authenticationManager());
        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(http)));
        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(securityConfigurerBuilder)));
        ServiceProviderSecurityConfigurer securityConfigurer = securityConfigurerBuilder.build();
        securityConfigurer.init(http);
        securityConfigurer.configure(http);
    }

    @Autowired(required = false)
    public void setServiceProviderConfigurers(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        this.serviceProviderConfigurers = serviceProviderConfigurers;
    }
}
