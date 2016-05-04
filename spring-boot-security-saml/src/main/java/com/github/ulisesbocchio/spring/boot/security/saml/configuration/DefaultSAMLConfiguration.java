package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.parser.ParserPoolHolder;

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
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
}
