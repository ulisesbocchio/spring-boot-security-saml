package com.github.ulisesbocchio.spring.boot.security.saml.annotation;

/**
 * @author Ulises Bocchio
 */

import com.github.ulisesbocchio.spring.boot.security.saml.configuration.DefaultSAMLConfiguration;
import com.github.ulisesbocchio.spring.boot.security.saml.configuration.SAMLServiceProviderSecurityConfiguration;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;

import java.lang.annotation.*;

/**
 * Main entry point for this Spring Boot plugin. This annotation enables the annotated Spring Boot Application as a
 * SAML 2.0 Service Provider, which basically configures Spring Security with Spring Security SAML to provide Service
 * Provider capabilities. Exposes to the users of this plugin the {@link ServiceProviderConfigurer} for customization of
 * the Service Provider, a java DSL that resembles the configuration style of {@link WebSecurityConfigurer} and it
 * provides one adapter with empty implementations, {@link ServiceProviderConfigurerAdapter} which is the preferable
 * class that users of this plugin will extend to customize the service provider. The following is a basic example:
 * <pre>
 *    {@literal @}Configuration
 *     public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
 *        {@literal @}Override
 *         public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
 *             serviceProvider
 *                 .metadataGenerator()
 *                 .entityId("localhost-demo")
 *             .and()
 *                 .sso()
 *                 .defaultSuccessURL("/home")
 *                 .idpSelectionPageURL("/idpselection")
 *             .and()
 *                 .logout()
 *                 .defaultTargetURL("/")
 *             .and()
 *                 .metadataManager()
 *                 .metadataLocations("classpath:/idp-ssocircle.xml")
 *                 .refreshCheckInterval(0)
 *             .and()
 *                 .extendedMetadata()
 *                 .idpDiscoveryEnabled(true)
 *             .and()
 *                 .keyManager()
 *                 .privateKeyDERLocation("classpath:/localhost.key.der")
 *                 .publicKeyPEMLocation("classpath:/localhost.cert");
 *         }
 *     }
 * </pre>
 * <p>
 * Also, most simple configurations could be accomplished without the use of this DSL, by just simply configuring
 * the appropriate properties exposed by {@link SAMLSSOProperties} on application.properties, application.yml or any
 * other Property Source.
 *
 * @author Ulises Bocchio
 * @see ServiceProviderConfigurerAdapter
 * @see ServiceProviderConfigurer
 * @see DefaultSAMLConfiguration
 * @see SAMLServiceProviderSecurityConfiguration
 * @see SAMLSSOProperties
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableConfigurationProperties(SAMLSSOProperties.class)
@Import({DefaultSAMLConfiguration.class, SAMLServiceProviderSecurityConfiguration.class})
public @interface EnableSAMLSSO {
}
