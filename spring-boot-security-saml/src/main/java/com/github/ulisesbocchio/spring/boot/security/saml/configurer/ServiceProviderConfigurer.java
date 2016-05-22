package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Interface to be implemented when using {@link EnableSAMLSSO} and wanting to further customize the SAML Service
 * Provider using the DSL provided by {@link ServiceProviderSecurityBuilder}, which exposes most aspects of configuring
 * Spring Security SAML. Users of this interface are encouraged to use {@link ServiceProviderConfigurerAdapter} which
 * is the default implementation with empty methods, so users can choose which method to actually override.
 * <p>
 * The following is a basic example:
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
 *                 .privateKeyDerLocation("classpath:/localhost.key.der")
 *                 .publicKeyPemLocation("classpath:/localhost.cert");
 *         }
 *     }
 * </pre>
 * </p>
 * A different method of configuration exists through configuration properties exposed by {@link SAMLSSOProperties}.
 *
 * @author Ulises Bocchio
 * @see ServiceProviderConfigurerAdapter
 * @see ServiceProviderSecurityBuilder
 * @see EnableSAMLSSO
 * @see SAMLSSOProperties
 */
public interface ServiceProviderConfigurer {

    /**
     * Allows for customization the SAML Service Provider. The {@code serviceProvider} argument exposes a bunch
     * of configurers with options to fully customize Spring Security SAML through a DSL-like configuration.
     * A different method of configuration exists through configuration properties exposed by {@link
     * SAMLSSOProperties}.
     *
     * @param serviceProvider
     * @throws Exception Any exception coming from {@link WebSecurityConfigurerAdapter}.
     * @see SAMLSSOProperties
     */
    void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception;

    /**
     * Allows for customization of the {@link HttpSecurity} object exposed by {@link WebSecurityConfigurerAdapter}.
     *
     * @param http the HttpSecurity object.
     * @throws Exception Any exception coming from {@link WebSecurityConfigurerAdapter}.
     */
    void configure(HttpSecurity http) throws Exception;

    /**
     * Allows for customization of the {@link WebSecurity} object exposed by {@link WebSecurityConfigurerAdapter}.
     *
     * @param web the WebSecurity object.
     * @throws Exception Any exception coming from {@link WebSecurityConfigurerAdapter}.
     */
    void configure(WebSecurity web);
}
