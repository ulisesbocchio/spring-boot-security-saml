package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import java.util.*;

/**
 * @author Ulises Bocchio
 */
@ConfigurationProperties(prefix = "saml.sso")
@Data
public class SAMLSSOProperties {
    @NestedConfigurationProperty
    private IdentityProvidersConfiguration idps = new IdentityProvidersConfiguration();
    @NestedConfigurationProperty
    private ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    @NestedConfigurationProperty
    private ExtendedMetadataDelegateConfiguration extendedDelegate = new ExtendedMetadataDelegateConfiguration();
    @NestedConfigurationProperty
    private AuthenticationProviderConfiguration authenticationProvider = new AuthenticationProviderConfiguration();
    @NestedConfigurationProperty
    private SAMLProcessorConfiguration samlProcessor = new SAMLProcessorConfiguration();
    @NestedConfigurationProperty
    private LogoutConfiguration logout = new LogoutConfiguration();
    @NestedConfigurationProperty
    private MetadataGeneratorConfiguration metadataGenerator = new MetadataGeneratorConfiguration();
    private String defaultSuccessURL = "/";
    private String defaultFailureURL = "/error";
    private String ssoProcessingURL = "/saml/SSO";
    private boolean enableSsoHoK = true;
    private String discoveryProcessingURL = "/saml/discovery";
    private String idpSelectionPageURL = "/idpselection";
    private String ssoLoginURL = "saml/login";
    @NestedConfigurationProperty
    private WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
    @NestedConfigurationProperty
    private KeystoreConfiguration keystore = new KeystoreConfiguration();
    @NestedConfigurationProperty
    private TLSConfiguration tls = new TLSConfiguration();
    @NestedConfigurationProperty
    private MetadataManagerConfiguration metadataManager = new MetadataManagerConfiguration();

    @Data
    public static class MetadataManagerConfiguration {
        private String defaultIDP;
        private String hostedSPName;
        private Integer refreshCheckInterval;
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
    public static class KeystoreConfiguration {
        String publicKeyPEMLocation;
        String privateKeyDERLocation;
        String storeLocation;
        String storePass;
        Map<String, String> keyPasswords = Collections.singletonMap("localhost", "");
        String defaultKey = "localhost";
    }

    @Data
    public static class MetadataGeneratorConfiguration {
        private String metadataURL = "/saml/metadata";
        private String entityId = "localhost";
        private boolean wantAssertionSigned = true;
        private boolean requestSigned = true;
        private Collection<String> nameId = null;
        private String entityBaseURL = null;
        private Collection<String> bindingsSSO = Arrays.asList("post", "artifact");
        private Collection<String> bindingsHoKSSO = Arrays.asList();
        private Collection<String> bindingsSLO = Arrays.asList("post", "redirect");
        private int assertionConsumerIndex = 0;
        private boolean includeDiscoveryExtension = true;
    }

    @Data
    public static class LogoutConfiguration {
        private String defaultTargetURL = "/";
        private String logoutURL = "/saml/logout";
        private String singleLogoutURL = "saml/SingleLogout";
        private boolean clearAuthentication = true;
        private boolean invalidateSession = false;
    }

    @Data
    public static class AuthenticationProviderConfiguration {
        private boolean forcePrincipalAsString = false;
        private boolean excludeCredential = false;
    }

    @Data
    public static class IdentityProvidersConfiguration {
        private String metadataLocation = "classpath:idp-metadata.xml";
    }

    @Data
    public static class ExtendedMetadataDelegateConfiguration {
        private Set<String> metadataTrustedKeys = null;
        private boolean metadataTrustCheck = false;
        private boolean forceMetadataRevocationCheck = false;
        private boolean metadataRequireSignature = false;
        private boolean requireValidMetadata = false;
    }

    @Data
    public static class SAMLProcessorConfiguration {
        private boolean redirect = true;
        private boolean post = true;
        private boolean artifact = true;
        private boolean soap = true;
        private boolean paos = true;
    }
}
