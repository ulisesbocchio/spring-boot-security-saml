package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

/**
 * Configuration Properties for {@link org.springframework.security.saml.SAMLAuthenticationProvider}
 *
 * @author Ulises Bocchio
 */
@Data
public class AuthenticationProviderProperties {

    /**
     * When false (default) the resulting Authentication object will include instance of SAMLCredential as a
     * credential value. The credential includes information related to the authentication process, received
     * attributes and is required for Single Logout. In case your application doesn't require the credential, it is
     * possible to exclude it from the Authentication object by setting this flag to true.
     */
    private boolean forcePrincipalAsString = false;

    /**
     * By default principal in the returned Authentication object is the NameID included in the authenticated
     * Assertion. The NameID is not serializable. Setting this value to true will force the NameID value to be a
     * String.
     */
    private boolean excludeCredential = false;
}
