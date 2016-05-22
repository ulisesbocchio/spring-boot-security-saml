package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.security.saml.SAMLConstants;

import java.util.Set;

/**
 * Properties for {@link org.springframework.security.saml.metadata.ExtendedMetadata}
 *
 * @author Ulises Bocchio
 */
@Data
public class ExtendedMetadataProperties {
    /**
     * Setting of the value determines whether the entity is deployed locally (hosted on the current installation) or
     * whether it's an entity deployed elsewhere.
     */
    private boolean local;

    /**
     * Local alias of the entity used for construction of well-known metadata address and determining target
     * entity from incoming requests.
     */
    private String alias;

    /**
     * When true IDP discovery will be invoked before SSO. Only valid for local entities.
     */
    private boolean idpDiscoveryEnabled;

    /**
     * URL of the IDP Discovery service user should be redirected to upon request to determine which IDP to use.
     * Value can override settings in the local SP metadata. Only valid for local entities.
     */
    private String idpDiscoveryURL;

    /**
     * URL where the discovery service should send back response to our discovery request. Only valid for local
     * entities.
     */
    private String idpDiscoveryResponseURL;

    /**
     * Indicates whether Enhanced Client/Proxy profile should be used for requests which support it. Only valid for
     * local entities.
     */
    private boolean ecpEnabled;

    /**
     * Profile used for trust verification, MetaIOP by default. Only relevant for local entities.
     */
    private String securityProfile = "metaiop";

    /**
     * Profile used for SSL/TLS trust verification, PKIX by default. Only relevant for local entities.
     */
    private String sslSecurityProfile = "pkix";

    /**
     * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
     */
    private String sslHostnameVerification = "default";

    /**
     * Key (stored in the local keystore) used for signing/verifying signature of messages sent/coming from this
     * entity. For local entities private key must be available, for remote entities only public key is required.
     */
    private String signingKey;

    /**
     * Algorithm used for creation of digital signatures of this entity. At the moment only used for metadata
     * signatures.
     * Only valid for local entities.
     */
    private String signingAlgorithm;

    /**
     * Flag indicating whether to sign metadata for this entity. Only valid for local entities.
     */
    private boolean signMetadata;

    /**
     * Name of generator for KeyInfo elements in metadata and signatures. At the moment only used for metadata
     * signatures.
     * Only valid for local entities.
     */
    private String keyInfoGeneratorName = SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;

    /**
     * Key (stored in the local keystore) used for encryption/decryption of messages coming/sent from this entity. For
     * local entities
     * private key must be available, for remote entities only public key is required.
     */
    private String encryptionKey;

    /**
     * Key used for verification of SSL/TLS connections. For local entities key is included in the generated metadata
     * when specified.
     * For remote entities key is used to for server authentication of SSL/TLS when specified and when MetaIOP security
     * profile is used.
     */
    private String tlsKey;

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is
     * null
     * all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys;

    /**
     * SAML specification mandates that incoming LogoutRequests must be authenticated.
     */
    private boolean requireLogoutRequestSigned = true;

    /**
     * Flag indicating whether incoming LogoutResposne messages must be authenticated.
     */
    private boolean requireLogoutResponseSigned;

    /**
     * If true received artifactResolve messages will require a signature, sent artifactResolve will be signed.
     */
    private boolean requireArtifactResolveSigned = true;

    /**
     * Flag indicating whether to support unsolicited responses (IDP-initialized SSO). Only valid for remote
     * entities.
     */
    private boolean supportUnsolicitedResponse = true;
}
