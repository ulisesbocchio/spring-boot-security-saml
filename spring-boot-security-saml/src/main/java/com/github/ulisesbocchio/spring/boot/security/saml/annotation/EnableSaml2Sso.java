package com.github.ulisesbocchio.spring.boot.security.saml.annotation;

/**
 * @author Ulises Bocchio
 */

import com.github.ulisesbocchio.spring.boot.security.saml.configuration.Saml2ServiceProviderSecurityConfiguration;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.Saml2SsoProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableOAuth2Client
@EnableConfigurationProperties(Saml2SsoProperties.class)
@Import({Saml2ServiceProviderSecurityConfiguration.class})
public @interface EnableSaml2Sso {
}
