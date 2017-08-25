package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLContextProviderLBProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLContextProviderProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.assertj.core.util.VisibleForTesting;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;

import java.util.Optional;

/**
 * Builder configurer that takes care of configuring/customizing the {@link SAMLContextProviderLB} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context. So if not {@link SAMLContextProvider} bean is defined, priority goes to a custom SAMLContextProvider
 * provided explicitly to this {@link SAMLContextProviderConfigurer}. And if not provided through the constructor, a
 * default implementation is instantiated.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getContextProvider()} and
 * {@link SAMLContextProviderProperties#getLb()} if no custom SAMLContextProvider or SAMLContextProviderLB
 * is provided. In other words, the user is able to configure the {@link SAMLContextProvider} through the
 * following properties:
 * <pre>
 *     saml.sso.context-provider.lb.scheme
 *     saml.sso.context-provider.lb.server-name
 *     saml.sso.context-provider.lb.include-server-port-in-request-url
 *     saml.sso.context-provider.lb.server-port
 *     saml.sso.context-provider.lb.context-path
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class SAMLContextProviderLBConfigurer extends SecurityConfigurerAdapter<Void, ServiceProviderBuilder> {

    private SAMLContextProviderLB samlContextProvider;

    private String scheme;
    private String serverName;
    private Boolean includeServerPortInRequestURL;
    private Integer serverPort;
    private String contextPath;
    private SAMLContextProviderLBProperties config;

    public SAMLContextProviderLBConfigurer() {

    }

    public SAMLContextProviderLBConfigurer(SAMLContextProviderLB samlContextProvider) {
        this.samlContextProvider = samlContextProvider;
    }

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getContextProvider().getLb();
    }

    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        SAMLContextProvider samlContextProviderBean = builder.getSharedObject(SAMLContextProvider.class);
        if (samlContextProviderBean == null) {
            if (samlContextProvider == null) {
                samlContextProvider = createDefaultSamlContextProviderLB();
                samlContextProvider.setScheme(Optional.ofNullable(scheme).orElseGet(config::getScheme));
                samlContextProvider.setServerName(Optional.ofNullable(serverName).orElseGet(config::getServerName));
                samlContextProvider.setIncludeServerPortInRequestURL(Optional.ofNullable(includeServerPortInRequestURL).orElseGet(config::getIncludeServerPortInRequestUrl));
                samlContextProvider.setServerPort(Optional.ofNullable(serverPort).orElseGet(config::getServerPort));
                samlContextProvider.setContextPath(Optional.ofNullable(contextPath).orElseGet(config::getContextPath));
            }
            builder.setSharedObject(SAMLContextProvider.class, samlContextProvider);
        }
    }

    @VisibleForTesting
    protected SAMLContextProviderLB createDefaultSamlContextProviderLB() {
        return new SAMLContextProviderLB();
    }

    /**
     * Scheme of the LB server - either http or https.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.context-provider.lb.scheme
     * </pre>
     * </p>
     *
     * @param scheme Scheme of the LB server - either http or https.
     * @return this configurer for further customization
     */
    public SAMLContextProviderLBConfigurer scheme(String scheme) {
        this.scheme = scheme;
        return this;
    }

    /**
     * Server name of the LB, e.g. www.myserver.com.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.context-provider.lb.server-name
     * </pre>
     * </p>
     *
     * @param serverName Server name of the LB, e.g. www.myserver.com.
     * @return this configurer for further customization
     */
    public SAMLContextProviderLBConfigurer serverName(String serverName) {
        this.serverName = serverName;
        return this;
    }

    /**
     * When true serverPort will be used in construction of LB requestURL.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.context-provider.lb.include-server-port-in-request-url
     * </pre>
     * </p>
     *
     * @param includeServerPortInRequestURL SWhen true serverPort will be used in construction of LB requestURL.
     * @return this configurer for further customization
     */
    public SAMLContextProviderLBConfigurer includeServerPortInRequestURL(boolean includeServerPortInRequestURL) {
        this.includeServerPortInRequestURL = includeServerPortInRequestURL;
        return this;
    }

    /**
     * Port of the server, in case value is &lt;= 0 port will not be included in the requestURL and port
     * from the original request will be used for getServerPort calls.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.context-provider.lb.server-port
     * </pre>
     * </p>
     *
     * @param serverPort Port of the server, in case value is &lt;= 0 port will not be included in the requestURL and port
     *                   from the original request will be used for getServerPort calls.
     * @return this configurer for further customization
     */
    public SAMLContextProviderLBConfigurer serverPort(int serverPort) {
        this.serverPort = serverPort;
        return this;
    }

    /**
     * Context path of the LB, must be starting with slash, e.g. /saml-extension.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.context-provider.lb.context-path
     * </pre>
     * </p>
     *
     * @param contextPath Context path of the LB, must be starting with slash, e.g. /saml-extension.
     * @return this configurer for further customization
     */
    public SAMLContextProviderLBConfigurer contextPath(String contextPath) {
        this.contextPath = contextPath;
        return this;
    }
}
