package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;

import java.util.Collection;
import java.util.Set;

/**
 * Configuration Properties for {@link org.springframework.security.saml.websso.WebSSOProfileOptions}
 *
 * @author Ulises Bocchio
 */
@Data
public class WebSSOProfileOptionProperties {

    /**
     * Binding to be used for for sending SAML message to IDP.
     */
    private String binding;

    /**
     * List of IDPs which are allowed to process the created AuthnRequest. IDP the request will be sent to is added
     * automatically. In case value is null the allowedIdps will not be included in the Scoping element.
     * <p>
     * Property includeScoping must be enabled for this value to take any effect.
     * </p>
     */
    private Set<String> allowedIdps;

    /**
     * Human readable name of the local entity.
     */
    private String providerName;

    /**
     * When set determines assertionConsumerService and binding to which should IDP send response. By default
     * service is determined automatically. Available indexes can be found in metadata of this service provider.
     */
    private Integer assertionConsumerIndex;

    /**
     * NameID to used or null to omit NameIDPolicy from request.
     */
    private String nameId;

    /**
     * Flag indicating whether IDP can create new user based on the current authentication request. Null value will
     * omit field from the request.
     */
    private Boolean allowCreate;

    /**
     * Whether the IdP should refrain from interacting with the user during the authentication process. Boolean
     * values will be marshalled to either "true" or "false".
     */
    private Boolean passive = false;

    /**
     * Whether to always force Authentication when redirected to the IDP or to allow IDP-managed sessions (basically disables Single Sign On for the local entity).
     */
    private Boolean forceAuthn = false;

    /**
     * True if scoping element should be included in the requests sent to IDP.
     */
    private Boolean includeScoping = true;

    /**
     * Null to skip proxyCount, 0 to disable proxying, &gt;0 to allow proxying
     */
    private Integer proxyCount = 2;

    /**
     * Relay state sent to the IDP as part of the authentication request. Value will be returned by IDP and made available
     * in the SAMLCredential after successful authentication.
     */
    private String relayState;

    /**
     * Enable different {@link org.opensaml.saml2.core.AuthnContext} to be sent and validated based on {@code authnContextComparison}.
     */
    private Collection<String> authnContexts;

    /**
     * Comparison to use for WebSSO requests. No change for null values.
     */
    private AuthnContextComparisonTypeEnumeration authnContextComparison = AuthnContextComparisonTypeEnumeration.EXACT;
}
