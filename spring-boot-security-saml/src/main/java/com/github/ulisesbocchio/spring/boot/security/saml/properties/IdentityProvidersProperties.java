package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;

/**
 * Configuration Properties For Identity Providers.
 *
 * @author Ulises Bocchio
 */
@Data
public class IdentityProvidersProperties {

    /**
     * Specify the location(s) of the metadata files to be loaded as {@link ResourceBackedMetadataProvider}
     */
    private String metadataLocation = "classpath:idp-metadata.xml";

    /**
     * Specify the location of the local SP_ metadata file to be loaded as {@link ResourceBackedMetadataProvider}
     */
    private String localMetadataLocation = null;
}
