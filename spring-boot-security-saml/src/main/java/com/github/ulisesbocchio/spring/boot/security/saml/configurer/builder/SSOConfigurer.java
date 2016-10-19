package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilderResult;
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
 *     saml.sso.default-success-url
 *     saml.sso.default-failure-url
 *     saml.sso.sso-processing-url
 *     saml.sso.enable-sso-hok
 *     saml.sso.discovery-processing-url
 *     saml.sso.idp-selection-page-url
 *     saml.sso.sso-login-url
 *     saml.sso.profile-options.binding
 *     saml.sso.profile-options.allowed-idps
 *     saml.sso.profile-options.provider-name
 *     saml.sso.profile-options.assertion-consumer-index
 *     saml.sso.profile-options.name-id
 *     saml.sso.profile-options.allow-create
 *     saml.sso.profile-options.passive
 *     saml.sso.profile-options.force-authn
 *     saml.sso.profile-options.include-scoping
 *     saml.sso.profile-options.proxy-count
 *     saml.sso.profile-options.relay-state
 *     saml.sso.profile-options.authn-contexts
 *     saml.sso.profile-options.authn-context-comparison
 *
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class SSOConfigurer extends SecurityConfigurerAdapter<ServiceProviderBuilderResult, ServiceProviderBuilder> {

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
    private SAMLEntryPoint samlEntryPointBean;

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        config = builder.getSharedObject(SAMLSSOProperties.class);
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        if (successHandler == null) {
            SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = createDefaultSuccessHandler();
            successRedirectHandler.setDefaultTargetUrl(Optional.ofNullable(defaultSuccessURL).orElseGet(config::getDefaultSuccessUrl));
            successHandler = postProcess(successRedirectHandler);
        }

        defaultFailureURL = Optional.ofNullable(defaultFailureURL).orElseGet(config::getDefaultFailureUrl);
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
        ssoProcessingURL = Optional.ofNullable(ssoProcessingURL).orElseGet(config::getSsoProcessingUrl);
        endpoints.setSsoProcessingURL(ssoProcessingURL);
        ssoFilter.setFilterProcessesUrl(ssoProcessingURL);

        SAMLWebSSOHoKProcessingFilter ssoHoKFilter = null;
        if (Optional.ofNullable(enableSsoHoK).orElseGet(config::isEnableSsoHok)) {
            ssoHoKFilter = createDefaultSamlHoKProcessingFilter();
            ssoHoKFilter.setAuthenticationSuccessHandler(successHandler);
            ssoHoKFilter.setAuthenticationManager(authenticationManager);
            ssoHoKFilter.setAuthenticationFailureHandler(failureHandler);
            ssoHoKProcessingURL = Optional.ofNullable(ssoHoKProcessingURL).orElseGet(config::getSsoHokProcessingUrl);
            endpoints.setSsoHoKProcessingURL(ssoHoKProcessingURL);
            ssoHoKFilter.setFilterProcessesUrl(ssoHoKProcessingURL);
        }

        SAMLDiscovery discoveryFilter = createDefaultSamlDiscoveryFilter();
        discoveryProcessingURL = Optional.ofNullable(discoveryProcessingURL).orElseGet(config::getDiscoveryProcessingUrl);
        endpoints.setDiscoveryProcessingURL(discoveryProcessingURL);
        discoveryFilter.setFilterProcessesUrl(discoveryProcessingURL);
        idpSelectionPageURL = Optional.ofNullable(idpSelectionPageURL).orElseGet(config::getIdpSelectionPageUrl);
        endpoints.setIdpSelectionPageURL(idpSelectionPageURL);
        discoveryFilter.setIdpSelectionPath(idpSelectionPageURL);

        SAMLEntryPoint entryPoint = Optional.ofNullable(samlEntryPointBean).orElseGet(this::createDefaultSamlEntryPoint);
        entryPoint.setDefaultProfileOptions(Optional.ofNullable(profileOptions).orElseGet(this::getProfileOptions));
        ssoLoginURL = Optional.ofNullable(ssoLoginURL).orElseGet(config::getSsoLoginUrl);
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
        options.setAllowedIDPs(properties.getAllowedIdps());
        options.setAssertionConsumerIndex(properties.getAssertionConsumerIndex());
        options.setAuthnContextComparison(properties.getAuthnContextComparison());
        options.setAuthnContexts(properties.getAuthnContexts());
        options.setBinding(properties.getBinding());
        options.setForceAuthN(properties.getForceAuthn());
        options.setIncludeScoping(properties.getIncludeScoping());
        options.setNameID(properties.getNameId());
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
     * Provide a specific {@link SAMLEntryPoint}.
     *
     * @param samlEntryPoint the actual entry point.
     * @return this configurer for further customization
     */
    public SSOConfigurer samlEntryPoint(SAMLEntryPoint samlEntryPoint) {
        this.samlEntryPointBean = samlEntryPoint;
        return this;
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
     *      saml.sso.default-success-url
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
     *      saml.sso.default-failure-url
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
     *      saml.sso.sso-processing-url
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
     *      saml.sso.sso-hok-Processing-url
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
     *      saml.sso.enable-sso-hok
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
     *      saml.sso.discovery-processing-url
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
     *      saml.sso.idp-selection-page-url
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
     *      saml.sso.sso-login-url
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
     *      saml.sso.profile-options.binding
     *      saml.sso.profile-options.allowed-idps
     *      saml.sso.profile-options.provider-name
     *      saml.sso.profile-options.assertion-consumer-index
     *      saml.sso.profile-options.name-id
     *      saml.sso.profile-options.allow-create
     *      saml.sso.profile-options.passive
     *      saml.sso.profile-options.force-authn
     *      saml.sso.profile-options.include-scoping
     *      saml.sso.profile-options.proxy-count
     *      saml.sso.profile-options.relay-state
     *      saml.sso.profile-options.authn-contexts
     *      saml.sso.profile-options.authn-context-comparison
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
