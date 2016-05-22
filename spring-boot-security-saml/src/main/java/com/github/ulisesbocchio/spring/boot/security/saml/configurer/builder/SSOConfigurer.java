package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.WebSSOProfileOptionProperties;
import org.assertj.core.util.VisibleForTesting;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.Optional;

/**
 * <p>
 * Builder configurer that takes care of configuring/customizing the {@link SAMLProcessingFilter},
 * {@link SAMLWebSSOHoKProcessingFilter}, {@link SAMLDiscovery}, and {@link SAMLEntryPoint} bean.
 * </p>
 * <p>
 * This configurer always instantiates its own {@link SAMLProcessingFilter},
 * {@link SAMLWebSSOHoKProcessingFilter}, {@link SAMLDiscovery}, and {@link SAMLEntryPoint} based on the specified
 * configuration.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties} for some DSL methods if they are not used.
 * In other words, the user is able to configure the filters through the following properties:
 * <pre>
 *     saml.sso.defaultSuccessURL
 *     saml.sso.defaultFailureURL
 *     saml.sso.ssoProcessingURL
 *     saml.sso.enableSsoHok
 *     saml.sso.discoveryProcessingURL
 *     saml.sso.idpSelectionPageURL
 *     saml.sso.ssoLoginURL
 *     saml.sso.profileOptions
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class SSOConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String defaultSuccessURL;
    private AuthenticationSuccessHandler successHandler;
    private String defaultFailureURL;
    private AuthenticationFailureHandler failureHandler;
    private String ssoProcessingURL;
    private Boolean enableSsoHoK;
    private String discoveryProcessingURL;
    private String idpSelectionPageURL;
    private String ssoLoginURL;
    private WebSSOProfileOptions profileOptions;
    private AuthenticationManager authenticationManager;
    private SAMLSSOProperties config;
    private ServiceProviderEndpoints endpoints;
    private String ssoHoKProcessingURL;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        config = builder.getSharedObject(SAMLSSOProperties.class);
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (successHandler == null) {
            SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = createDefaultSuccessHandler();
            successRedirectHandler.setDefaultTargetUrl(Optional.ofNullable(defaultSuccessURL).orElseGet(config::getDefaultSuccessURL));
            successHandler = postProcess(successRedirectHandler);
        }

        defaultFailureURL = Optional.ofNullable(defaultFailureURL).orElseGet(config::getDefaultFailureURL);
        if (failureHandler == null) {
            SimpleUrlAuthenticationFailureHandler authenticationFailureHandler = createDefaultFailureHandler();
            authenticationFailureHandler.setDefaultFailureUrl(defaultFailureURL);
            failureHandler = postProcess(authenticationFailureHandler);
        }
        endpoints.setDefaultFailureURL(defaultFailureURL);


        SAMLProcessingFilter ssoFilter = createDefaultSamlProcessingFilter();
        ssoFilter.setAuthenticationManager(authenticationManager);
        ssoFilter.setAuthenticationSuccessHandler(successHandler);
        ssoFilter.setAuthenticationFailureHandler(failureHandler);
        ssoProcessingURL = Optional.ofNullable(ssoProcessingURL).orElseGet(config::getSsoProcessingURL);
        endpoints.setSsoProcessingURL(ssoProcessingURL);
        ssoFilter.setFilterProcessesUrl(ssoProcessingURL);

        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = null;
        if (Optional.ofNullable(enableSsoHoK).orElseGet(config::isEnableSsoHok)) {
            ssoHoKFilter = createDefaultSamlHoKProcessingFilter();
            ssoHoKFilter.setAuthenticationSuccessHandler(successHandler);
            ssoHoKFilter.setAuthenticationManager(authenticationManager);
            ssoHoKFilter.setAuthenticationFailureHandler(failureHandler);
            ssoHoKProcessingURL = Optional.ofNullable(ssoHoKProcessingURL).orElseGet(config::getSsoHokProcessingURL);
            endpoints.setSsoHoKProcessingURL(ssoHoKProcessingURL);
            ssoHoKFilter.setFilterProcessesUrl(ssoHoKProcessingURL);
        }

        SAMLDiscovery discoveryFilter = createDefaultSamlDiscoveryFilter();
        discoveryProcessingURL = Optional.ofNullable(discoveryProcessingURL).orElseGet(config::getDiscoveryProcessingURL);
        endpoints.setDiscoveryProcessingURL(discoveryProcessingURL);
        discoveryFilter.setFilterProcessesUrl(discoveryProcessingURL);
        idpSelectionPageURL = Optional.ofNullable(idpSelectionPageURL).orElseGet(config::getIdpSelectionPageURL);
        endpoints.setIdpSelectionPageURL(idpSelectionPageURL);
        discoveryFilter.setIdpSelectionPath(idpSelectionPageURL);

        SAMLEntryPoint entryPoint = createDefaultSamlEntryPoint();
        entryPoint.setDefaultProfileOptions(Optional.ofNullable(profileOptions).orElseGet(this::getProfileOptions));
        ssoLoginURL = Optional.ofNullable(ssoLoginURL).orElseGet(config::getSsoLoginURL);
        endpoints.setSsoLoginURL(ssoLoginURL);
        entryPoint.setFilterProcessesUrl(ssoLoginURL);

        builder.setSharedObject(SAMLProcessingFilter.class, ssoFilter);
        builder.setSharedObject(SAMLWebSSOHoKProcessingFilter.class, ssoHoKFilter);
        builder.setSharedObject(SAMLDiscovery.class, discoveryFilter);
        builder.setSharedObject(SAMLEntryPoint.class, entryPoint);
    }

    private WebSSOProfileOptions getProfileOptions() {
        WebSSOProfileOptionProperties properties = config.getProfileOptions();
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        options.setAllowCreate(properties.getAllowCreate());
        options.setAllowedIDPs(properties.getAllowedIDPs());
        options.setAssertionConsumerIndex(properties.getAssertionConsumerIndex());
        options.setAuthnContextComparison(properties.getAuthnContextComparison());
        options.setAuthnContexts(properties.getAuthnContexts());
        options.setBinding(properties.getBinding());
        options.setForceAuthN(properties.getForceAuthn());
        options.setIncludeScoping(properties.getIncludeScoping());
        options.setNameID(properties.getNameID());
        options.setPassive(properties.getPassive());
        options.setProviderName(properties.getProviderName());
        options.setProxyCount(properties.getProxyCount());
        options.setRelayState(properties.getRelayState());
        return options;
    }

    @VisibleForTesting
    protected SAMLWebSSOHoKProcessingFilter createDefaultSamlHoKProcessingFilter() {
        return new SAMLWebSSOHoKProcessingFilter();
    }

    @VisibleForTesting
    protected SAMLEntryPoint createDefaultSamlEntryPoint() {
        return new SAMLEntryPoint();
    }

    @VisibleForTesting
    protected SAMLDiscovery createDefaultSamlDiscoveryFilter() {
        return new SAMLDiscovery();
    }

    @VisibleForTesting
    protected SAMLProcessingFilter createDefaultSamlProcessingFilter() {
        return new SAMLProcessingFilter();
    }

    @VisibleForTesting
    protected SimpleUrlAuthenticationFailureHandler createDefaultFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler();
    }

    @VisibleForTesting
    protected SavedRequestAwareAuthenticationSuccessHandler createDefaultSuccessHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative to
     * the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name (such as
     * "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also supported.
     * Not Relevant if {@link #successHandler(AuthenticationSuccessHandler)} is used.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.defaultSuccessURL
     * </pre>
     * </p>
     *
     * @param defaultSuccessURL the default target URL
     * @return this configurer for further customization
     */
    public SSOConfigurer defaultSuccessURL(String defaultSuccessURL) {
        this.defaultSuccessURL = defaultSuccessURL;
        return this;
    }

    /**
     * Provide a specific {@link AuthenticationSuccessHandler} to be invoked on successful authentication. Overrides
     * value set by {@link #defaultSuccessURL(String)}.
     *
     * @param successHandler the actual success handler.
     * @return this configurer for further customization
     */
    public SSOConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    /**
     * The URL which will be used as the failure destination. Not relevant if using {@link
     * #failureHandler(AuthenticationFailureHandler)}.
     * Default is {@code "/error"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.defaultFailureURL
     * </pre>
     * </p>
     *
     * @param defaultFailureURL the failure URL, for example "/loginFailed.jsp".
     * @return this configurer for further customization
     */
    public SSOConfigurer defaultFailureURL(String defaultFailureURL) {
        this.defaultFailureURL = defaultFailureURL;
        return this;
    }

    /**
     * Provide a specific {@link AuthenticationFailureHandler} to be invoked on unsuccessful authentication. Overrides
     * value set by {@link #defaultFailureURL(String)}.
     *
     * @param failureHandler the actual failure handler.
     * @return this configurer for further customization
     */
    public SSOConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    /**
     * The URL that the {@link SAMLProcessingFilter} will be listening to.
     * Default is {@code "/saml/SSO"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.ssoProcessingURL
     * </pre>
     * </p>
     *
     * @param ssoProcessingURL the URL that the {@link SAMLProcessingFilter} will be listening to.
     * @return this configurer for further customization
     */
    public SSOConfigurer ssoProcessingURL(String ssoProcessingURL) {
        this.ssoProcessingURL = ssoProcessingURL;
        return this;
    }

    /**
     * The URL that the {@link SAMLWebSSOHoKProcessingFilter} will be listening to.
     * Default is {@code "/saml/HoKSSO"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.ssoHokProcessingURL
     * </pre>
     * </p>
     *
     * @param ssoHoKProcessingURL the URL that the {@link SAMLWebSSOHoKProcessingFilter} will be listening to.
     * @return this configurer for further customization
     */
    public SSOConfigurer ssoHoKProcessingURL(String ssoHoKProcessingURL) {
        this.ssoHoKProcessingURL = ssoHoKProcessingURL;
        return this;
    }

    /**
     * Whether to enable the {@link SAMLWebSSOHoKProcessingFilter} filter or not.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.enableSsoHok
     * </pre>
     * </p>
     *
     * @param enableSsoHoK true if HoK Filter is enabled.
     * @return this configurer for further customization
     */
    public SSOConfigurer enableSsoHoK(boolean enableSsoHoK) {
        this.enableSsoHoK = enableSsoHoK;
        return this;
    }

    /**
     * The URL that the {@link SAMLDiscovery} filter will be listening to.
     * Default is {@code "/saml/discovery"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.discoveryProcessingURL
     * </pre>
     * </p>
     *
     * @param discoveryProcessingURL the URL that the {@link SAMLDiscovery} filter will be listening to.
     * @return this configurer for further customization
     */
    public SSOConfigurer discoveryProcessingURL(String discoveryProcessingURL) {
        this.discoveryProcessingURL = discoveryProcessingURL;
        return this;
    }

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default IDP will
     * always be used.
     * Default is {@code "/idpselection"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.idpSelectionPageURL
     * </pre>
     * </p>
     *
     * @param idpSelectionPageURL selection path.
     * @return this configurer for further customization
     */
    public SSOConfigurer idpSelectionPageURL(String idpSelectionPageURL) {
        this.idpSelectionPageURL = idpSelectionPageURL;
        return this;
    }

    /**
     * The URL that the {@link SAMLEntryPoint} filter will be listening to.
     * Default is {@code "/saml/login"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.ssoLoginURL
     * </pre>
     * </p>
     *
     * @param ssoLoginURL the URL that the {@link SAMLEntryPoint} filter will be listening to.
     * @return this configurer for further customization
     */
    public SSOConfigurer ssoLoginURL(String ssoLoginURL) {
        this.ssoLoginURL = ssoLoginURL;
        return this;
    }

    /**
     * Provide a specific {@link WebSSOProfileOptions} options.
     * <p>
     * Alternatively use properties:
     * <pre>
     *      saml.sso.profileOptions.binding
     *      saml.sso.profileOptions.allowedIDPs
     *      saml.sso.profileOptions.providerName
     *      saml.sso.profileOptions.assertionConsumerIndex
     *      saml.sso.profileOptions.nameID
     *      saml.sso.profileOptions.allowCreate
     *      saml.sso.profileOptions.passive
     *      saml.sso.profileOptions.forceAuthn
     *      saml.sso.profileOptions.includeScoping
     *      saml.sso.profileOptions.proxyCount
     *      saml.sso.profileOptions.relayState
     *      saml.sso.profileOptions.authnContexts
     *      saml.sso.profileOptions.authnContextComparison
     * </pre>
     * </p>
     *
     * @param profileOptions the SSO Profile Options.
     * @return this configurer for further customization
     */
    public SSOConfigurer profileOptions(WebSSOProfileOptions profileOptions) {
        this.profileOptions = profileOptions;
        return this;
    }
}
