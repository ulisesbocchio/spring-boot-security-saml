package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Configuration Properties for {@link org.springframework.security.saml.metadata.ExtendedMetadataDelegate}
 *
 * @author Ulises Bocchio
 */
@Data
public class ExtendedMetadataDelegateProperties {

    /**
     * Keys stored in the KeyManager which can be used to verify whether signature of the metadata is trusted.
     * If not set any key stored in the keyManager is considered as trusted.
     */
    private Set<String> metadataTrustedKeys = new HashSet<>();

    /**
     * When true metadata signature will be verified for trust using PKIX with metadataTrustedKeys
     * as anchors.
     */
    private boolean metadataTrustCheck = false;

    /**
     * Determines whether check for certificate revocation should always be done as part of the PKIX validation.
     * Revocation is evaluated by the underlaying JCE implementation and depending on configuration may include CRL
     * and OCSP verification of the certificate in question. When set to false revocation is only performed when
     * MetadataManager includes CRLs.
     */
    private boolean forceMetadataRevocationCheck = false;

    /**
     * When set to true metadata from this provider should only be accepted when correctly signed and verified.
     * Metadata with an invalid signature or signed by a not-trusted credential will be ignored.
     */
    private boolean metadataRequireSignature = false;

    /**
     * Sets whether the metadata returned by queries must be valid.
     */
    private boolean requireValidMetadata = false;
}
