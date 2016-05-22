package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;

import java.util.Arrays;
import java.util.Collection;

/**
 * Configuration Properties for {@link MetadataGenerator} {@link org.springframework.security.saml.metadata.MetadataGeneratorFilter}
 * and {@link MetadataDisplayFilter}
 *
 * @author Ulises Bocchio
 */
@Data
public class MetadataGeneratorProperties {

    /**
     * {@link MetadataDisplayFilter} processing URL. Defines which URL will display the Service Provider Metadata.
     */
    private String metadataURL = "/saml/metadata";

    /**
     * This Service Provider's SAML Entity ID. Used as entity id for generated requests from this Service Provider.
     */
    private String entityId = "localhost";

    /**
     * Local ID. Used as part of Entity Descriptor.
     */
    private String id = null;

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
    private Collection<String> nameId = MetadataGenerator.defaultNameID;

    /**
     * This Service Provider's entity base URL. Provide if base URL cannot be inferred by using the hostname where
     * the Service Provider will be running. I.E. if running on the cloud behind a load balancer.
     */
    private String entityBaseURL = null;

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On. Ordering of bindings
     * affects inclusion in the generated metadata. Supported values are: "artifact" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"), "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
     * and "paos" (or "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"). The following bindings are included by default:
     * "artifact", "post".
     */
    private Collection<String> bindingsSSO = Arrays.asList("post", "artifact");

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On Holder of Key. Ordering of
     * bindings affects inclusion in the generated metadata. Supported values are: "artifact" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") and "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").
     * By default there are no included bindings for the profile.
     */
    private Collection<String> bindingsHokSSO = Arrays.asList();

    /**
     * List of bindings to be included in the generated metadata for Single Logout. Ordering of bindings affects
     * inclusion in the generated metadata. Supported values are: "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
     * and "redirect" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"). The following bindings are
     * included
     * by default: "post", "redirect".
     */
    private Collection<String> bindingsSLO = Arrays.asList("post", "redirect");

    /**
     * Generated assertion consumer service with the index equaling set value will be marked as default. Use
     * negative value to skip the default attribute altogether.
     */
    private int assertionConsumerIndex = 0;

    /**
     * When true discovery profile extension metadata pointing to the default SAMLEntryPoint will be generated and
     * stored in the generated metadata document.
     */
    private boolean includeDiscoveryExtension = true;
}
