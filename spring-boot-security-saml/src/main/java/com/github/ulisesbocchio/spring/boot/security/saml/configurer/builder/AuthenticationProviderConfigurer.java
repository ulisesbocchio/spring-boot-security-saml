package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.AuthenticationProviderProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.user.SimpleSAMLUserDetailsService;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.Optional;

/**
 * Builder configurer that takes care of configuring/customizing a {@link SAMLAuthenticationProvider} for the
 * SAML 2.0 Service Provider.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context. If not {@link SAMLAuthenticationProvider} is present in the Spring Context, priority goes to a custom
 * provider provided explicitly to this configurer through the constructor. And if not provided through the constructor,
 * a default implementation is instantiated that is configurable through the DSL methods.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getAuthenticationProvider()} if no custom
 * Authentication Provider is provided, for some DSL methods if they are not used. In other words, the user is able to
 * configure the Authentication Provider through the following properties:
 * <pre>
 *     saml.sso.authenticationProvider.forcePrincipalAsString
 *     saml.sso.authenticationProvider.excludeCredential
 * </pre>
 * <p/>
 *
 * @author Ulises Bocchio
 */
public class AuthenticationProviderConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private Boolean excludeCredential = null;
    private Boolean forcePrincipalAsString = null;
    private SAMLUserDetailsService userDetailsService;
    private SAMLAuthenticationProvider authenticationProvider;
    private AuthenticationProviderProperties config;
    private SAMLAuthenticationProvider authenticationProviderBean;

    /**
     * Provide the provider to be used.
     *
     * @param provider the {@link SAMLAuthenticationProvider} to be used.
     */
    public AuthenticationProviderConfigurer(SAMLAuthenticationProvider provider) {
        authenticationProvider = provider;
    }

    /**
     * Default Constructor
     */
    public AuthenticationProviderConfigurer() {
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        authenticationProviderBean = builder.getSharedObject(SAMLAuthenticationProvider.class);
        config = builder.getSharedObject(SAMLSSOProperties.class).getAuthenticationProvider();
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (authenticationProviderBean == null) {
            if (authenticationProvider == null) {
                authenticationProvider = new SAMLAuthenticationProvider();
                authenticationProvider.setExcludeCredential(Optional.ofNullable(excludeCredential).
                        orElseGet(config::isExcludeCredential));

                authenticationProvider.setForcePrincipalAsString(Optional.ofNullable(forcePrincipalAsString)
                        .orElseGet(config::isForcePrincipalAsString));

                authenticationProvider.setUserDetails(postProcess(Optional.ofNullable(userDetailsService)
                        .orElseGet(SimpleSAMLUserDetailsService::new)));
            }
            builder.setSharedObject(SAMLAuthenticationProvider.class, authenticationProvider);
        }
    }

    /**
     * When false (default) the resulting Authentication object will include instance of SAMLCredential as a credential
     * value. The credential includes information related to the authentication process, received attributes and is
     * required for Single Logout. In case your application doesn't require the credential, it is possible to exclude
     * it from the Authentication object by setting this flag to true.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.authenticationProvider.excludeCredential
     * </pre>
     *
     * @param excludeCredential false to include credential in the Authentication object, true to exclude it
     * @return This Configurer to keep customizing the Authentication Provider
     */
    public AuthenticationProviderConfigurer excludeCredential(boolean excludeCredential) {
        this.excludeCredential = excludeCredential;
        return this;
    }

    /**
     * By default principal in the returned Authentication object is the NameID included in the authenticated
     * Assertion.
     * The NameID is not serializable. Setting this value to true will force the NameID value to be a String.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.authenticationProvider.forcePrincipalAsString
     * </pre>
     *
     * @param forcePrincipalAsString true to force principal to be a String
     * @return This Configurer to keep customizing the Authentication Provider
     */
    public AuthenticationProviderConfigurer forcePrincipalAsString(boolean forcePrincipalAsString) {
        this.forcePrincipalAsString = forcePrincipalAsString;
        return this;
    }

    /**
     * The user details can be optionally set and is automatically called while user SAML assertion is validated.
     *
     * @param userDetailsService the user details service to use.
     * @return This Configurer to keep customizing the Authentication Provider
     */
    public AuthenticationProviderConfigurer userDetailsService(SAMLUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        return this;
    }
}
