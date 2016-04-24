package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.metadata.ExtendedMetadata;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Ulises Bocchio
 */
@ConfigurationProperties(prefix = "saml.sso")
@Data
public class SAML2SsoProperties {
    @NestedConfigurationProperty
    private IdentityProvidersConfiguration idps = new IdentityProvidersConfiguration();
    @NestedConfigurationProperty
    private ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    @NestedConfigurationProperty
    private ExtendedMetadataDelegateConfiguration extendedDelegate = new ExtendedMetadataDelegateConfiguration();
    @NestedConfigurationProperty
    private AuthenticationProviderConfiguration authenticationProvider = new AuthenticationProviderConfiguration();
    private String metadataLocation = "classpath:idp-metadata.xml";
    @NestedConfigurationProperty
    private SAMLProcessorConfiguration samlProcessor = new SAMLProcessorConfiguration();

    @Data
    public static class AuthenticationProviderConfiguration {
        private boolean forcePrincipalAsString = false;
        private boolean excludeCredential = false;
    }

    @Data
    public static class IdentityProvidersConfiguration {
        private Set<String> metadataLocations= new HashSet<>();
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
