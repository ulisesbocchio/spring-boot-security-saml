package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.parser.ParserPoolHolder;

/**
 * Default Spring Security SAML Configuration beans. Override any of this beans if necessary.
 * This beans, required by Spring Security SAML, are injected/used throughout the Service Provider configuration
 * process.
 *
 * @author Ulises Bocchio
 * @see SAMLServiceProviderSecurityConfiguration
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
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
}
