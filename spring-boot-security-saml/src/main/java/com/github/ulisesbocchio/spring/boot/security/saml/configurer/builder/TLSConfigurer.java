package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * <p>
 * Builder configurer that takes care of configuring/customizing the {@link TLSProtocolConfigurer} bean.
 * </p>
 * <p>
 * This configurer always instantiates its own {@link TLSProtocolConfigurer}.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getTls()} for some the DSL methods if they are
 * not used. In other words, the user is able to configure the TLSProtocolConfigurer through the following properties:
 * <pre>
 *     saml.sso.tls.protocolName
 *     saml.sso.tls.protocolPort
 *     saml.sso.tls.keyManager
 *     saml.sso.tls.sslHostnameVerification
 *     saml.sso.tls.trustedKeys
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class TLSConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String protocolName;
    private Integer protocolPort;
    private String sslHostnameVerification;
    private Set<String> trustedKeys;
    private SAMLSSOProperties.TLSConfiguration config;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getTls();
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
        configurer.setProtocolName(Optional.ofNullable(protocolName).orElseGet(config::getProtocolName));
        configurer.setProtocolPort(Optional.ofNullable(protocolPort).orElseGet(config::getProtocolPort));
        configurer.setSslHostnameVerification(Optional.ofNullable(sslHostnameVerification).orElseGet(config::getSslHostnameVerification));
        configurer.setTrustedKeys(Optional.ofNullable(trustedKeys).orElseGet(config::getTrustedKeys));
        builder.setSharedObject(TLSProtocolConfigurer.class, configurer);
    }

    /**
     * Name of protocol (ID) to register to HTTP Client, https by default.
     * Default is {@code "https"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.tls.protocolName
     * </pre>
     * </p>
     *
     * @param protocolName the protocol
     * @return this configurer for further customization
     */
    public TLSConfigurer protocolName(String protocolName) {
        this.protocolName = protocolName;
        return this;
    }

    /**
     * Default port for protocol.
     * Default is {@code 443}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.tls.protocolPort
     * </pre>
     * </p>
     *
     * @param protocolPort the protocol port
     * @return this configurer for further customization
     */
    public TLSConfigurer protocolPort(int protocolPort) {
        this.protocolPort = protocolPort;
        return this;
    }

    /**
     * Hostname verifier to use for verification of SSL connections. Default value is "default", other supported
     * options
     * are "defaultAndLocalhost", "strict" and "allowAll".
     * Default is {@code "default"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.tls.sslHostnameVerification
     * </pre>
     * </p>
     *
     * @param sslHostnameVerification hostname verification mode.
     * @return this configurer for further customization
     */
    public TLSConfigurer sslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
        return this;
    }

    /**
     * When not set all certificates included in the keystore will be used as trusted certificate authorities. When
     * specified,
     * only keys with the defined aliases will be used for trust evaluation.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.tls.trustedKeys
     * </pre>
     * </p>
     *
     * @param trustedKeys trusted keys.
     * @return this configurer for further customization
     */
    public TLSConfigurer trustedKeys(String... trustedKeys) {
        this.trustedKeys = Arrays.stream(trustedKeys).collect(toSet());
        return this;
    }
}
