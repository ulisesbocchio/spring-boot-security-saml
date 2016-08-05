package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;

/**
 * Configuration Properties exposed to allow customization of the Service Provider enabled by {@link EnableSAMLSSO}.
 * All configuration properties have their counterpart on the Java DSL provided by {@link
 * ServiceProviderSecurityBuilder}.
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
    private IdentityProvidersProperties idps = new IdentityProvidersProperties();

    /**
     * Extended Metadata Configuration for local and remote entities.
     */
    @NestedConfigurationProperty
    private ExtendedMetadataProperties extendedMetadata = new ExtendedMetadataProperties();

    /**
     * Extended Metadata Delegate configuration used to wrap Metadata Providers with extended metadata and other
     * options.
     */
    @NestedConfigurationProperty
    private ExtendedMetadataDelegateProperties extendedDelegate = new ExtendedMetadataDelegateProperties();

    /**
     * SAML Authentication Provider Configuration options.
     */
    @NestedConfigurationProperty
    private AuthenticationProviderProperties authenticationProvider = new AuthenticationProviderProperties();

    /**
     * SAML Processor configuration for sending and receiving SAML messages.
     */
    @NestedConfigurationProperty
    private SAMLProcessorProperties samlProcessor = new SAMLProcessorProperties();

    /**
     * Configuration for local and global logout options.
     */
    @NestedConfigurationProperty
    private LogoutProperties logout = new LogoutProperties();

    /**
     * Configuration for metadata generation filters and local entity configuration.
     */
    @NestedConfigurationProperty
    private MetadataGeneratorProperties metadataGenerator = new MetadataGeneratorProperties();

    /**
     * Configuration Options for the Web SSO Profile used for sending requests to the IDP.
     */
    @NestedConfigurationProperty
    private WebSSOProfileOptionProperties profileOptions = new WebSSOProfileOptionProperties();

    /**
     * Configuration for the {@link KeyManager} that manages encryption keys and certificates.
     */
    @NestedConfigurationProperty
    private KeyManagerProperties keyManager = new KeyManagerProperties();

    /**
     * Configuration options for the TLS Protocol.
     */
    @NestedConfigurationProperty
    private TLSProperties tls = new TLSProperties();

    /**
     * Configuration options for the {@link MetadataManager}
     */
    @NestedConfigurationProperty
    private MetadataManagerProperties metadataManager = new MetadataManagerProperties();

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * alwaysUseDefaultTargetUrl property is set to true. If not set, defaults to /. It will be treated as relative to
     * the web-app's context path, and should include the leading /. Alternatively, inclusion of a scheme name (such as
     * "http://" or "https://") as the prefix will denote a fully-qualified URL and this is also supported.
     */
    private String defaultSuccessUrl = "/";

    /**
     * The URL which will be used as the failure destination.
     */
    private String defaultFailureUrl = "/error";

    /**
     * The URL that the {@link SAMLProcessingFilter} will be listening to.
     */
    private String ssoProcessingUrl = "/saml/SSO";

    /**
     * The URL that the {@link SAMLWebSSOHoKProcessingFilter} will be listening to. Only relevant if {@code
     * enableSsoHok} is true.
     */
    private String ssoHokProcessingUrl = "/saml/HoKSSO";

    /**
     * Whether to enable the {@link SAMLWebSSOHoKProcessingFilter} filter or not.
     */
    private boolean enableSsoHok = true;

    /**
     * The URL that the {@link SAMLDiscovery} filter will be listening to.
     */
    private String discoveryProcessingUrl = "/saml/discovery";

    /**
     * Sets path where request dispatcher will send user for IDP selection. In case it is null the default IDP will
     * always be used.
     */
    private String idpSelectionPageUrl = "/idpselection";

    /**
     * The URL that the {@link SAMLEntryPoint} filter will be listening to.
     */
    private String ssoLoginUrl = "saml/login";
}
