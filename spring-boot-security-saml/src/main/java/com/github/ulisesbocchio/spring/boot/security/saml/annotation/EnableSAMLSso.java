package com.github.ulisesbocchio.spring.boot.security.saml.annotation;

/**
 * @author Ulises Bocchio
 */

import com.github.ulisesbocchio.spring.boot.security.saml.configuration.DefaultSAMLConfiguration;
import com.github.ulisesbocchio.spring.boot.security.saml.configuration.SAMLServiceProviderSecurityConfiguration;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableConfigurationProperties(SAMLSsoProperties.class)
@Import({DefaultSAMLConfiguration.class, SAMLServiceProviderSecurityConfiguration.class})
public @interface EnableSAMLSso {
}
