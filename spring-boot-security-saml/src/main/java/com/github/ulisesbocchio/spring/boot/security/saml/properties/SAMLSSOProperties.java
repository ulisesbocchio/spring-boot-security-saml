package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import lombok.Data;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.*;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import java.util.*;

/**
 * Configuration Properties exposed to allow customization of the Service Provider enabled by {@link EnableSAMLSSO}.
 * All configuration properties have their counterpart on the Java DSL provided by {@link ServiceProviderSecurityBuilder}.
 *
 * @author Ulises Bocchio
 */
@ConfigurationProperties(prefix = "saml.sso")
@Data
public class SAMLSSOProperties {
    /**
     * Identity Provider Metadata Configuration.
     */
    @NestedConfigurationProperty
    private IdentityProvidersConfiguration idps = new IdentityProvidersConfiguration();

    /**
     * Extended Metadata Configuration for local and remote entities.
     */
    @NestedConfigurationProperty
    private ExtendedMetadata extendedMetadata = new ExtendedMetadata();

    /**
     * Extended Metadata Delegate configuration used to wrap Metadata Providers with extended metadata and other options.
     */
    @NestedConfigurationProperty
    private ExtendedMetadataDelegateConfiguration extendedDelegate = new ExtendedMetadataDelegateConfiguration();

    /**
     * SAML Authentication Provider Configuration options.
     */
    @NestedConfigurationProperty
    private AuthenticationProviderConfiguration authenticationProvider = new AuthenticationProviderConfiguration();

    /**
     * SAML Processor configuration for sending and receiving SAML messages.
     */
    @NestedConfigurationProperty
    private SAMLProcessorConfiguration samlProcessor = new SAMLProcessorConfiguration();

    /**
     * Configuration for local and global logout options.
     */
    @NestedConfigurationProperty
    private LogoutConfiguration logout = new LogoutConfiguration();

    /**
     * Configuration for metadata generation filters and local entity configuration.
     */
    @NestedConfigurationProperty
    private MetadataGeneratorConfiguration metadataGenerator = new MetadataGeneratorConfiguration();

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the alwaysUseDefaultTargetUrl
     * property is set to true. If not set, defaults to /. It will be treated as relative to the web-app's context path,
     * and should include the leading /. Alternatively, inclusion of a scheme name (such as "http://" or "https://") as
     * the prefix will denote a fully-qualified URL and this is also supported.
     */
    private String defaultSuccessURL = "/";

    /**
     * The URL which will be used as the failure destination.
     */
    private String defaultFailureURL = "/error";

    /**
     * The URL that the {@link SAMLProcessingFilter} will be listening to.
     */
    private String ssoProcessingURL = "/saml/SSO";

    /**
     * Whether to enable the {@link SAMLWebSSOHoKProcessingFilter} filter or not.
     */
    private boolean enableSsoHoK = true;

    /**
     * The URL that the {@link SAMLDiscovery} filter will be listening to.
     */
    private String discoveryProcessingURL = "/saml/discovery";

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default IDP will always be used.
     */
    private String idpSelectionPageURL = "/idpselection";

    /**
     * The URL that the {@link SAMLEntryPoint} filter will be listening to.
     */
    private String ssoLoginURL = "saml/login";

    /**
     * Configuration Options for the Web SSO Profile used for sending requests to the IDP.
     */
    @NestedConfigurationProperty
    private WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();

    /**
     * Configuration for the {@link KeyManager} that manages encryption keys and certificates.
     */
    @NestedConfigurationProperty
    private KeyManagerConfiguration keyManager = new KeyManagerConfiguration();

    /**
     * Configuration options for the TLS Protocol.
     */
    @NestedConfigurationProperty
    private TLSConfiguration tls = new TLSConfiguration();

    /**
     * Configuration options for the {@link MetadataManager}
     */
    @NestedConfigurationProperty
    private MetadataManagerConfiguration metadataManager = new MetadataManagerConfiguration();

    @Data
    public static class MetadataManagerConfiguration {
        /**
         * Sets name of IDP to be used as default.
         */
        private String defaultIDP;

        /**
         * Sets nameID of SP hosted on this machine. This can either be called from springContext or automatically during
         * invocation of metadata generation filter.
         */
        private String hostedSPName;

        /**
         * Interval in milliseconds used for re-verification of metadata and their reload. Upon trigger each provider
         * is asked to return it's metadata, which might trigger their reloading. In case metadata is reloaded the manager
         * is notified and automatically refreshes all internal data by calling refreshMetadata.
         * <p>
         * In case the value is smaller than zero the timer is not created.
         * </p>
         */
        private Long refreshCheckInterval = -1L;
    }

    @Data
    public static class TLSConfiguration {
        /**
         * Name of protocol to register.
         */
        private String protocolName = "https";

        /*
         * Default port of protocol.
         */
        private int protocolPort = 443;

        /**
         * Storage for all available keys.
         */
        private KeyManager keyManager;

        /**
         * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
         */
        private String sslHostnameVerification = "default";

        /**
         * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is null
         * all keys in the keyStore will be treated as trusted.
         */
        private Set<String> trustedKeys;
    }

    @Data
    public static class KeyManagerConfiguration {
        /**
         * Specify a PEM certificate location. Used in conjunction with privateKeyDERLocation.
         */
        String publicKeyPEMLocation;

        /**
         * Specify a DER private key location. Used in conjunction with publicKeyPEMLocation.
         */
        String privateKeyDERLocation;

        /**
         * The location of KeyStore resource. If used, privateKeyDERLocation and privateKeyDERLocation are ignored.
         */
        String storeLocation;

        /**
         * The KeyStore password. Not relevant when using privateKeyDERLocation and privateKeyDERLocation.
         */
        String storePass;

        /**
         * They KeyStore private key passwords by key name.
         */
        Map<String, String> keyPasswords = Collections.singletonMap("localhost", "");

        /**
         * The default key name to use for encryption.
         */
        String defaultKey = "localhost";
    }

    @Data
    public static class MetadataGeneratorConfiguration {

        /**
         * {@link MetadataDisplayFilter} processing URL. Defines which URL will display the Service Provider Metadata.
         */
        private String metadataURL = "/saml/metadata";

        /**
         * This Service Provider's SAML Entity ID. Used as entity id for generated requests from this Service Provider.
         */
        private String entityId = "localhost";

        /**
         * Whether incoming SAML assertions should be signed or not.
         */
        private boolean wantAssertionSigned = true;

        /**
         * Whether Authentication Requests should be signed by this Service Provider or not.
         */
        private boolean requestSigned = true;

        /**
         * NameIDs to be included in generated metadata.
         */
        private Collection<String> nameId = null;

        /**
         * This Service Provider's entity base URL. Provide if base URL cannot be inferred by using the hostname where
         * the Service Provider will be running. I.E. if running on the cloud behind a load balancer.
         */
        private String entityBaseURL = null;

        /**
         * List of bindings to be included in the generated metadata for Web Single Sign-On. Ordering of bindings affects inclusion in
         * the generated metadata. Supported values are: "artifact" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),
         * "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") and "paos" (or "urn:oasis:names:tc:SAML:2.0:bindings:PAOS").
         * The following bindings are included by default: "artifact", "post".
         */
        private Collection<String> bindingsSSO = Arrays.asList("post", "artifact");

        /**
         * List of bindings to be included in the generated metadata for Web Single Sign-On Holder of Key. Ordering of bindings
         * affects inclusion in the generated metadata. Supported values are: "artifact"
         * (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") and "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").
         * By default there are no included bindings for the profile.
         */
        private Collection<String> bindingsHoKSSO = Arrays.asList();

        /**
         * List of bindings to be included in the generated metadata for Single Logout. Ordering of bindings affects inclusion in
         * the generated metadata. Supported values are: "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") and
         * "redirect" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"). The following bindings are included by default:
         * "post", "redirect".
         */
        private Collection<String> bindingsSLO = Arrays.asList("post", "redirect");

        /**
         * Generated assertion consumer service with the index equaling set value will be marked as default. Use negative value
         * to skip the default attribute altogether.
         */
        private int assertionConsumerIndex = 0;

        /**
         * When true discovery profile extension metadata pointing to the default SAMLEntryPoint will be generated and stored in
         * the generated metadata document.
         */
        private boolean includeDiscoveryExtension = true;
    }

    @Data
    public static class LogoutConfiguration {

        /**
         * Supplies the default target Url that will be used if no saved request is found in the session, or the alwaysUseDefaultTargetUrl
         * property is set to true. If not set, defaults to /. It will be treated as relative to the web-app's context path, and should
         * include the leading /. Alternatively, inclusion of a scheme name (such as "http://" or "https://") as the prefix will denote
         * a fully-qualified URL and this is also supported.
         */
        private String defaultTargetURL = "/";

        /**
         * Sets the URL used to determine if the {@link SAMLLogoutFilter} is invoked.
         */
        private String logoutURL = "/saml/logout";

        /**
         * Sets the URL used to determine if the {@link SAMLLogoutProcessingFilter} is invoked.
         */
        private String singleLogoutURL = "saml/SingleLogout";

        /**
         * If true, removes the Authentication from the SecurityContext to prevent issues with concurrent requests.
         */
        private boolean clearAuthentication = true;

        /**
         * Causes the HttpSession to be invalidated when this LogoutHandler is invoked. Defaults to true.
         */
        private boolean invalidateSession = false;
    }

    @Data
    public static class AuthenticationProviderConfiguration {

        /**
         * When false (default) the resulting Authentication object will include instance of SAMLCredential as a credential
         * value. The credential includes information related to the authentication process, received attributes and is
         * required for Single Logout. In case your application doesn't require the credential, it is possible to exclude it
         * from the Authentication object by setting this flag to true.
         */
        private boolean forcePrincipalAsString = false;

        /**
         * By default principal in the returned Authentication object is the NameID included in the authenticated Assertion.
         * The NameID is not serializable. Setting this value to true will force the NameID value to be a String.
         */
        private boolean excludeCredential = false;
    }

    @Data
    public static class IdentityProvidersConfiguration {

        /**
         * Specify the location(s) of the metadata files to be loaded as {@link ResourceBackedMetadataProvider}
         */
        private String metadataLocation = "classpath:idp-metadata.xml";
    }

    @Data
    public static class ExtendedMetadataDelegateConfiguration {

        /**
         * Keys stored in the KeyManager which can be used to verify whether signature of the metadata is trusted.
         * If not set any key stored in the keyManager is considered as trusted.
         */
        private Set<String> metadataTrustedKeys = null;

        /**
         * When true metadata signature will be verified for trust using PKIX with metadataTrustedKeys
         * as anchors.
         */
        private boolean metadataTrustCheck = false;

        /**
         * Determines whether check for certificate revocation should always be done as part of the PKIX validation. Revocation
         * is evaluated by the underlaying JCE implementation and depending on configuration may include CRL and OCSP verification
         * of the certificate in question. When set to false revocation is only performed when MetadataManager includes CRLs.
         */
        private boolean forceMetadataRevocationCheck = false;

        /**
         * When set to true metadata from this provider should only be accepted when correctly signed and verified. Metadata with
         * an invalid signature or signed by a not-trusted credential will be ignored.
         */
        private boolean metadataRequireSignature = false;

        /**
         * Sets whether the metadata returned by queries must be valid.
         */
        private boolean requireValidMetadata = false;
    }

    @Data
    public static class SAMLProcessorConfiguration {

        /**
         * Disable/Enable HTTP Redirect Bindings.
         */
        private boolean redirect = true;

        /**
         * Disable/Enable HTTP POST Bindings.
         */
        private boolean post = true;

        /**
         * Disable/Enable HTTP Artifact Bindings.
         */
        private boolean artifact = true;

        /**
         * Disable/Enable SOAP Bindings.
         */
        private boolean soap = true;

        /**
         * Disable/Enable PAOS Bindings.
         */
        private boolean paos = true;
    }
}
