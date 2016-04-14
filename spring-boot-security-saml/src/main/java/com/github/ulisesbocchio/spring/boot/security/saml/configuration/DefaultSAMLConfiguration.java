package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.websso.*;

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

    //Bean Name is important as it is autowired by name in SAMLAuthenticationProvider
    @Bean(name = "webSSOprofileConsumer")
    @ConditionalOnMissingBean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }


    //Bean Name is important as it is autowired by name in SAMLAuthenticationProvider
    @Bean(name = "hokWebSSOprofileConsumer")
    @ConditionalOnMissingBean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "webSSOprofile")
    @ConditionalOnMissingBean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "ecpProfile")
    @ConditionalOnMissingBean
    public WebSSOProfileECPImpl ecpProfile() {
        return new WebSSOProfileECPImpl();
    }

    //Bean Name is important as it is autowired by name in SAMLEntryPoint
    @Bean(name = "hokWebSSOProfile")
    @ConditionalOnMissingBean
    public WebSSOProfileHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileHoKImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public SingleLogoutProfile logoutProfile() {
        return new SingleLogoutProfileImpl();
    }
}
