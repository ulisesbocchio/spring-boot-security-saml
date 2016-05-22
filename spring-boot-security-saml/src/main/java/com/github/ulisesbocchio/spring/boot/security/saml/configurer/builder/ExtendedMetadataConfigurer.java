package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.ExtendedMetadataProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * Builder configurer that takes care of configuring/customizing the {@link ExtendedMetadata} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link ExtendedMetadata} bean is defined, priority goes to a custom ExtendedMetadata provided explicitly
 * to this configurer through the constructor. And if not provided through the constructor, a default implementation is
 * instantiated that is configurable through the DSL methods.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getExtendedMetadata()} if no custom Extended
 * Metadata is provided, for some DSL methods if they that are not used. In other words, the user is able to configure
 * the Extended Metadata through the following properties:
 * <pre>
 *     saml.sso.extendedMetadata.local
 *     saml.sso.extendedMetadata.alias
 *     saml.sso.extendedMetadata.idpDiscoveryEnabled
 *     saml.sso.extendedMetadata.idpDiscoveryURL
 *     saml.sso.extendedMetadata.idpDiscoveryResponseURL
 *     saml.sso.extendedMetadata.ecpEnabled
 *     saml.sso.extendedMetadata.securityProfile
 *     saml.sso.extendedMetadata.sslSecurityProfile
 *     saml.sso.extendedMetadata.sslHostnameVerification
 *     saml.sso.extendedMetadata.signingKey
 *     saml.sso.extendedMetadata.signMetadata
 *     saml.sso.extendedMetadata.keyInfoGeneratorName
 *     saml.sso.extendedMetadata.encryptionKey
 *     saml.sso.extendedMetadata.tlsKey
 *     saml.sso.extendedMetadata.trustedKeys
 *     saml.sso.extendedMetadata.requireLogoutRequestSigned
 *     saml.sso.extendedMetadata.requireLogoutResponseSigned
 *     saml.sso.extendedMetadata.requireArtifactResolveSigned
 *     saml.sso.extendedMetadata.supportUnsolicitedResponse
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class ExtendedMetadataConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private ExtendedMetadata extendedMetadataBean;
    private ExtendedMetadata extendedMetadata;
    private ExtendedMetadataProperties extendedMetadataConfig;

    private Boolean local;
    private Boolean idpDiscoveryEnabled;
    private Boolean ecpEnabled;
    private Boolean signMetadata;
    private Boolean requireLogoutRequestSigned;
    private Boolean requireLogoutResponseSigned;
    private Boolean requireArtifactResolveSigned;
    private Boolean supportUnsolicitedResponse;
    private String alias;
    private String idpDiscoveryURL;
    private String idpDiscoveryResponseURL;
    private String securityProfile;
    private String sslSecurityProfile;
    private String sslHostnameVerification;
    private String signingKey;
    private String signingAlgorithm;
    private String keyInfoGeneratorName;
    private String encryptionKey;
    private String tlsKey;
    private Set<String> trustedKeys;

    public ExtendedMetadataConfigurer() {

    }

    public ExtendedMetadataConfigurer(ExtendedMetadata extendedMetadata) {
        this.extendedMetadata = extendedMetadata;
    }

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        extendedMetadataBean = builder.getSharedObject(ExtendedMetadata.class);
        extendedMetadataConfig = builder.getSharedObject(SAMLSSOProperties.class).getExtendedMetadata();

    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        if (extendedMetadataBean == null) {
            if (extendedMetadata == null) {
                extendedMetadata = new ExtendedMetadata();
                extendedMetadata.setLocal(Optional.ofNullable(local).orElseGet(extendedMetadataConfig::isLocal));
                extendedMetadata.setIdpDiscoveryEnabled(Optional.ofNullable(idpDiscoveryEnabled).orElseGet(extendedMetadataConfig::isIdpDiscoveryEnabled));
                extendedMetadata.setEcpEnabled(Optional.ofNullable(ecpEnabled).orElseGet(extendedMetadataConfig::isEcpEnabled));
                extendedMetadata.setSignMetadata(Optional.ofNullable(signMetadata).orElseGet(extendedMetadataConfig::isSignMetadata));
                extendedMetadata.setRequireLogoutRequestSigned(Optional.ofNullable(requireLogoutRequestSigned).orElseGet(extendedMetadataConfig::isRequireLogoutRequestSigned));
                extendedMetadata.setRequireLogoutResponseSigned(Optional.ofNullable(requireLogoutResponseSigned).orElseGet(extendedMetadataConfig::isRequireLogoutResponseSigned));
                extendedMetadata.setRequireArtifactResolveSigned(Optional.ofNullable(requireArtifactResolveSigned).orElseGet(extendedMetadataConfig::isRequireArtifactResolveSigned));
                extendedMetadata.setSupportUnsolicitedResponse(Optional.ofNullable(supportUnsolicitedResponse).orElseGet(extendedMetadataConfig::isSupportUnsolicitedResponse));
                extendedMetadata.setAlias(Optional.ofNullable(alias).orElseGet(extendedMetadataConfig::getAlias));
                extendedMetadata.setIdpDiscoveryURL(Optional.ofNullable(idpDiscoveryURL).orElseGet(extendedMetadataConfig::getIdpDiscoveryURL));
                extendedMetadata.setIdpDiscoveryResponseURL(Optional.ofNullable(idpDiscoveryResponseURL).orElseGet(extendedMetadataConfig::getIdpDiscoveryResponseURL));
                extendedMetadata.setSecurityProfile(Optional.ofNullable(securityProfile).orElseGet(extendedMetadataConfig::getSecurityProfile));
                extendedMetadata.setSslSecurityProfile(Optional.ofNullable(sslSecurityProfile).orElseGet(extendedMetadataConfig::getSslSecurityProfile));
                extendedMetadata.setSslHostnameVerification(Optional.ofNullable(sslHostnameVerification).orElseGet(extendedMetadataConfig::getSslHostnameVerification));
                extendedMetadata.setSigningKey(Optional.ofNullable(signingKey).orElseGet(extendedMetadataConfig::getSigningKey));
                extendedMetadata.setSigningAlgorithm(Optional.ofNullable(signingAlgorithm).orElseGet(extendedMetadataConfig::getSigningAlgorithm));
                extendedMetadata.setKeyInfoGeneratorName(Optional.ofNullable(keyInfoGeneratorName).orElseGet(extendedMetadataConfig::getKeyInfoGeneratorName));
                extendedMetadata.setEncryptionKey(Optional.ofNullable(encryptionKey).orElseGet(extendedMetadataConfig::getEncryptionKey));
                extendedMetadata.setTlsKey(Optional.ofNullable(tlsKey).orElseGet(extendedMetadataConfig::getTlsKey));
                extendedMetadata.setTrustedKeys(Optional.ofNullable(trustedKeys).orElseGet(extendedMetadataConfig::getTrustedKeys));
            }
            builder.setSharedObject(ExtendedMetadata.class, extendedMetadata);
        }
    }

    /**
     * When set to true entity is treated as locally deployed and will be able to accept messages on endpoints
     * determined
     * by the selected alias.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.local
     * </pre>
     * </p>
     *
     * @param local true when entity is deployed locally
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer local(Boolean local) {
        this.local = local;
        return this;
    }

    /**
     * When true IDP discovery will be invoked before initializing WebSSO, unless IDP is already specified inside
     * SAMLContext.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.idpDiscoveryEnabled
     * </pre>
     * </p>
     *
     * @param idpDiscoveryEnabled true when IDP Discovery is enabled
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer idpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
        this.idpDiscoveryEnabled = idpDiscoveryEnabled;
        return this;
    }

    /**
     * Indicates whether Enhanced Client/Proxy profile should be used for requests which support it. Only valid for
     * local entities.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.ecpEnabled
     * </pre>
     * </p>
     *
     * @param ecpEnabled true if ECP is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer ecpEnabled(boolean ecpEnabled) {
        this.ecpEnabled = ecpEnabled;
        return this;
    }

    /**
     * Flag indicating whether to sign metadata for this entity. Only valid for local entities.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.signMetadata
     * </pre>
     * </p>
     *
     * @param signMetadata true if sign metadata is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer signMetadata(boolean signMetadata) {
        this.signMetadata = signMetadata;
        return this;
    }

    /**
     * SAML specification mandates that incoming LogoutRequests must be authenticated.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.requireLogoutRequestSigned
     * </pre>
     * </p>
     *
     * @param requireLogoutRequestSigned true is logout request signed is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer requireLogoutRequestSigned(boolean requireLogoutRequestSigned) {
        this.requireLogoutRequestSigned = requireLogoutRequestSigned;
        return this;
    }

    /**
     * Flag indicating whether incoming LogoutResposne messages must be authenticated.
     * Default is {@code false}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.requireLogoutResponseSigned
     * </pre>
     * </p>
     *
     * @param requireLogoutResponseSigned true is logout response signed is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer requireLogoutResponseSigned(boolean requireLogoutResponseSigned) {
        this.requireLogoutResponseSigned = requireLogoutResponseSigned;
        return this;
    }

    /**
     * If true received artifactResolve messages will require a signature, sent artifactResolve will be signed.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.requireArtifactResolveSigned
     * </pre>
     * </p>
     *
     * @param requireArtifactResolveSigned true is require artifactResolve signed is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer requireArtifactResolveSigned(boolean requireArtifactResolveSigned) {
        this.requireArtifactResolveSigned = requireArtifactResolveSigned;
        return this;
    }

    /**
     * Flag indicating whether to support unsolicited responses (IDP-initialized SSO). Only valid for remote
     * entities.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.supportUnsolicitedResponse
     * </pre>
     * </p>
     *
     * @param supportUnsolicitedResponse true is support unsolicited response is enabled.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer supportUnsolicitedResponse(boolean supportUnsolicitedResponse) {
        this.supportUnsolicitedResponse = supportUnsolicitedResponse;
        return this;
    }

    /**
     * Local alias of the entity used for construction of well-known metadata address and determining target
     * entity from incoming requests.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.alias
     * </pre>
     * </p>
     *
     * @param alias the actual alias.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer alias(String alias) {
        this.alias = alias;
        return this;
    }

    /**
     * URL of the IDP Discovery service user should be redirected to upon request to determine which IDP to use.
     * Value can override settings in the local SP metadata. Only valid for local entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.idpDiscoveryURL
     * </pre>
     * </p>
     *
     * @param idpDiscoveryURL the idp discovery page URL.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer idpDiscoveryURL(String idpDiscoveryURL) {
        this.idpDiscoveryURL = idpDiscoveryURL;
        return this;
    }

    /**
     * URL where the discovery service should send back response to our discovery request. Only valid for local
     * entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.idpDiscoveryResponseURL
     * </pre>
     * </p>
     *
     * @param idpDiscoveryResponseURL the idp discovery response page URL.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer idpDiscoveryResponseURL(String idpDiscoveryResponseURL) {
        this.idpDiscoveryResponseURL = idpDiscoveryResponseURL;
        return this;
    }

    /**
     * Profile used for trust verification, MetaIOP by default. Only relevant for local entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.securityProfile
     * </pre>
     * </p>
     *
     * @param securityProfile the profile type.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer securityProfile(String securityProfile) {
        this.securityProfile = securityProfile;
        return this;
    }

    /**
     * Profile used for SSL/TLS trust verification, PKIX by default. Only relevant for local entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.sslSecurityProfile
     * </pre>
     * </p>
     *
     * @param sslSecurityProfile the profile type.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer sslSecurityProfile(String sslSecurityProfile) {
        this.sslSecurityProfile = sslSecurityProfile;
        return this;
    }

    /**
     * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
     * Default is {@code "default"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.sslHostnameVerification
     * </pre>
     * </p>
     *
     * @param sslHostnameVerification the ssl hostname verification type.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer sslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
        return this;
    }

    /**
     * Key (stored in the local keyManager) used for signing/verifying signature of messages sent/coming from this
     * entity. For local entities private key must be available, for remote entities only public key is required.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.signingKey
     * </pre>
     * </p>
     *
     * @param signingKey the id of the signing/verifying key as it appears in the Keystore.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer signingKey(String signingKey) {
        this.signingKey = signingKey;
        return this;
    }

    /**
     * Algorithm used for creation of digital signatures of this entity. At the moment only used for metadata
     * signatures.
     * Only valid for local entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.signingAlgorithm
     * </pre>
     * </p>
     *
     * @param signingAlgorithm the signing algorithm ID.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer signingAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
        return this;
    }

    /**
     * Name of generator for KeyInfo elements in metadata and signatures. At the moment only used for metadata
     * signatures.
     * Only valid for local entities.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.keyInfoGeneratorName
     * </pre>
     * </p>
     *
     * @param keyInfoGeneratorName name of generator.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer keyInfoGeneratorName(String keyInfoGeneratorName) {
        this.keyInfoGeneratorName = keyInfoGeneratorName;
        return this;
    }

    /**
     * Key (stored in the local keyManager) used for encryption/decryption of messages coming/sent from this entity. For
     * local entities private key must be available, for remote entities only public key is required.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.encryptionKey
     * </pre>
     * </p>
     *
     * @param encryptionKey the key to use.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer encryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
        return this;
    }

    /**
     * Key used for verification of SSL/TLS connections. For local entities key is included in the generated metadata
     * when specified.
     * For remote entities key is used to for server authentication of SSL/TLS when specified and when MetaIOP security
     * profile is used.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.tlsKey
     * </pre>
     * </p>
     *
     * @param tlsKey the key to use.
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer tlsKey(String tlsKey) {
        this.tlsKey = tlsKey;
        return this;
    }

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is
     * null all keys in the keyStore will be treated as trusted.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.extendedMetadata.trustedKeys
     * </pre>
     * </p>
     *
     * @param trustedKeys the trusted key names
     * @return this configurer for further customization
     */
    public ExtendedMetadataConfigurer trustedKeys(String... trustedKeys) {
        this.trustedKeys = Arrays.stream(trustedKeys).collect(toSet());
        return this;
    }
}
