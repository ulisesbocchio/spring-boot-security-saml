package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.websso.*;

import java.util.Collection;
import java.util.List;

/**
 * Default Spring Security SAML Configuration. Any of this Beans could be
 * overridden.
 *
 * @author Ulises Bocchio
 */
@Configuration
public class DefaultSAMLConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    @ConditionalOnMissingBean
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean(initMethod = "initialize")
    @ConditionalOnMissingBean
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean
    @ConditionalOnMissingBean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLAuthenticationProvider
    @Bean(name = "webSSOprofileConsumer")
    @ConditionalOnMissingBean(name = "webSSOprofileConsumer")
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLAuthenticationProvider
    @Bean(name = "hokWebSSOprofileConsumer")
    @ConditionalOnMissingBean(name = "hokWebSSOprofileConsumer")
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "webSSOprofile")
    @ConditionalOnMissingBean(name = "webSSOprofile")
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "ecpProfile")
    @ConditionalOnMissingBean(name = "ecpProfile")
    public WebSSOProfileECPImpl ecpProfile() {
        return new WebSSOProfileECPImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "hokWebSSOProfile")
    @ConditionalOnMissingBean(name = "hokWebSSOProfile")
    public WebSSOProfileHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileHoKImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public SingleLogoutProfile logoutProfile() {
        return new SingleLogoutProfileImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    @ConditionalOnMissingBean
    public CachingMetadataManager metadataManager() throws MetadataProviderException, ResourceException {
        return new CachingMetadataManager(null);
    }

    @Bean
    public KeyManager dummyKeyManager() {
        return new EmptyKeyManager();
    }

    @Bean
    SAMLProcessor dummySAMLProcessor() {
        return new SAMLProcessorImpl((Collection<SAMLBinding>) null);
    }
}
