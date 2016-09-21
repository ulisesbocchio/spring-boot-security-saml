package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilderResult;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.LogoutProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.assertj.core.util.VisibleForTesting;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.util.Optional;

/**
 * <p>
 * Builder configurer that takes care of configuring/customizing the {@link SAMLLogoutFilter} bean and
 * {@link SAMLLogoutProcessingFilter} bean.
 * </p>
 * <p>
 * This configurer always instantiates its own {@link SAMLLogoutFilter} and {@link SAMLLogoutProcessingFilter} based on
 * the specified configuration.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getLogout()} for some the DSL methods if they
 * are
 * not used. In other words, the user is able to configure the filters through the following properties:
 * <pre>
 *     saml.sso.logout.default-target-url
 *     saml.sso.logout.logout-url
 *     saml.sso.logout.single-logout-url
 *     saml.sso.logout.clear-authentication
 *     saml.sso.logout.invalidate-session
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class LogoutConfigurer extends SecurityConfigurerAdapter<ServiceProviderBuilderResult, ServiceProviderBuilder> {
    private String defaultTargetURL;
    private String logoutURL;
    private String singleLogoutURL;
    private Boolean clearAuthentication;
    private Boolean invalidateSession;
    private LogoutSuccessHandler successHandler;
    private LogoutHandler localHandler;
    private LogoutHandler globalHandler;
    private LogoutProperties config;
    private ServiceProviderEndpoints endpoints;

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getLogout();
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @SuppressWarnings("Duplicates")
    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        if (successHandler == null) {
            SimpleUrlLogoutSuccessHandler successLogoutHandler = createDefaultSuccessHandler();
            defaultTargetURL = Optional.ofNullable(defaultTargetURL).orElseGet(config::getDefaultTargetUrl);
            successLogoutHandler.setDefaultTargetUrl(defaultTargetURL);
            endpoints.setDefaultTargetURL(defaultTargetURL);
            successHandler = postProcess(successLogoutHandler);
        }

        if (localHandler == null) {
            SecurityContextLogoutHandler logoutHandler = createDefaultLocalHandler();
            logoutHandler.setInvalidateHttpSession(Optional.ofNullable(invalidateSession).orElseGet(config::isInvalidateSession));
            logoutHandler.setClearAuthentication(Optional.ofNullable(clearAuthentication).orElseGet(config::isClearAuthentication));
            localHandler = postProcess(logoutHandler);
        }

        if (globalHandler == null) {
            SecurityContextLogoutHandler logoutHandler = createDefaultGlobalHandler();
            logoutHandler.setInvalidateHttpSession(Optional.ofNullable(invalidateSession).orElseGet(config::isInvalidateSession));
            logoutHandler.setClearAuthentication(Optional.ofNullable(clearAuthentication).orElseGet(config::isClearAuthentication));
            globalHandler = postProcess(logoutHandler);
        }

        SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(successHandler, new LogoutHandler[]{localHandler}, new LogoutHandler[]{globalHandler});
        logoutURL = Optional.ofNullable(logoutURL).orElseGet(config::getLogoutUrl);
        endpoints.setLogoutURL(logoutURL);
        samlLogoutFilter.setFilterProcessesUrl(logoutURL);

        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(successHandler, globalHandler);
        singleLogoutURL = Optional.ofNullable(singleLogoutURL).orElseGet(config::getSingleLogoutUrl);
        samlLogoutProcessingFilter.setFilterProcessesUrl(singleLogoutURL);
        endpoints.setSingleLogoutURL(singleLogoutURL);

        builder.setSharedObject(SAMLLogoutFilter.class, samlLogoutFilter);
        builder.setSharedObject(SAMLLogoutProcessingFilter.class, samlLogoutProcessingFilter);
    }

    @VisibleForTesting
    protected SecurityContextLogoutHandler createDefaultLocalHandler() {
        return new SecurityContextLogoutHandler();
    }

    @VisibleForTesting
    protected SecurityContextLogoutHandler createDefaultGlobalHandler() {
        return new SecurityContextLogoutHandler();
    }

    @VisibleForTesting
    protected SimpleUrlLogoutSuccessHandler createDefaultSuccessHandler() {
        return new SimpleUrlLogoutSuccessHandler();
    }

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative to
     * the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name (such as
     * "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also supported.
     * Default is {@code "/"}. Not relevant if {@link #successHandler(LogoutSuccessHandler)} is used.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.logout.default-target-url
     * </pre>
     * </p>
     *
     * @param url the default target URL
     * @return this configurer for further customization
     */
    public LogoutConfigurer defaultTargetURL(String url) {
        defaultTargetURL = url;
        return this;
    }

    /**
     * Sets the URL used to determine if the {@link SAMLLogoutFilter} is invoked.
     * Default is {@code "/saml/logout"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.logout.logout-url
     * </pre>
     * </p>
     *
     * @param url the url used to invoke the {@link SAMLLogoutFilter}.
     * @return this configurer for further customization
     */
    public LogoutConfigurer logoutURL(String url) {
        logoutURL = url;
        return this;
    }

    /**
     * Sets the URL used to determine if the {@link SAMLLogoutProcessingFilter} is invoked.
     * Default is {@code "/saml/SingleLogout"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.logout.single-logout-url
     * </pre>
     * </p>
     *
     * @param url the url used to invoke the {@link SAMLLogoutProcessingFilter}.
     * @return this configurer for further customization
     */
    public LogoutConfigurer singleLogoutURL(String url) {
        singleLogoutURL = url;
        return this;
    }

    /**
     * If true, removes the Authentication from the SecurityContext to prevent issues with concurrent requests.
     * Default is {@code true}. Not relevant if {@link #localHandler(LogoutHandler)} is used.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.logout.clear-authentication
     * </pre>
     * </p>
     *
     * @param value true if you wish to clear the Authentication from the SecurityContext (default) or false if the
     *              Authentication
     *              should not be removed.
     * @return this configurer for further customization
     */
    public LogoutConfigurer clearAuthentication(Boolean value) {
        clearAuthentication = value;
        return this;
    }

    /**
     * Causes the HttpSession to be invalidated when this LogoutHandler is invoked. Defaults to true.
     * Default is {@code false}. Not relevant if {@link #localHandler(LogoutHandler)} is used.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.logout.invalidate-session
     * </pre>
     * </p>
     *
     * @param value true if you wish the session to be invalidated or false (default) if it should not be.
     * @return this configurer for further customization
     */
    public LogoutConfigurer invalidateSession(Boolean value) {
        invalidateSession = value;
        return this;
    }

    /**
     * Handler to be invoked upon successful logout. Overrides value set by {@link #defaultTargetURL(String)}.
     *
     * @param handler the handler to invoke upon successful logout.
     * @return this configurer for further customization
     */
    public LogoutConfigurer successHandler(LogoutSuccessHandler handler) {
        successHandler = handler;
        return this;
    }

    /**
     * Handler to be invoked when local logout is selected. Overrides values set by {@link #clearAuthentication} and
     * {@link #invalidateSession} for local logout.
     *
     * @param handler the handler to be invoked.
     * @return this configurer for further customization
     */
    public LogoutConfigurer localHandler(LogoutHandler handler) {
        localHandler = handler;
        return this;
    }

    /**
     * Handler to be invoked when global logout is selected. Overrides values set by {@link #clearAuthentication} and
     * {@link #invalidateSession} for global logout.
     *
     * @param handler the handler to be invoked.
     * @return this configurer for further customization
     */
    public LogoutConfigurer globalHandler(LogoutHandler handler) {
        globalHandler = handler;
        return this;
    }
}
