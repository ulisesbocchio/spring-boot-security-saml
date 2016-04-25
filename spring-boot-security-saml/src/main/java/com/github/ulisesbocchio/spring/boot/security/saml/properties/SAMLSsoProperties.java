package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import java.util.Collection;
import java.util.Set;

/**
 * @author Ulises Bocchio
 */
@ConfigurationProperties(prefix = "saml.sso")
@Data
public class SAMLSsoProperties {
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

    @Data
    public static class MetadataGeneratorConfiguration {
        private String metadataURL = "/saml/metadata";
        private String entityId = "localhost";
        private boolean wantAssertionSigned = true;
        private boolean requestSigned = true;
        private Collection<String> nameId = null;
        private String entityBaseURL = null;
        private Collection<String> bindingsHoKSSO = null;
        private Collection<String> bindingsSLO = null;
        private Collection<String> bindingsSSO = null;
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
