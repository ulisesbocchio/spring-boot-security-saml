package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

import java.util.Collections;
import java.util.Set;

/**
 * Configuration Properties for {@link org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer}
 *
 * @author Ulises Bocchio
 */
@Data
public class TLSProperties {
    /**
     * Name of protocol to register.
     */
    private String protocolName = "https";

    /**
     * Default port of protocol.
     */
    private int protocolPort = 443;

    /**
     * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
     */
    private String sslHostnameVerification = "default";

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is
     * null all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys = Collections.EMPTY_SET;
}
