package com.github.ulisesbocchio.spring.boot.security.saml.properties;

import lombok.Data;

/**
 * Configuration Properties for {@link org.springframework.security.saml.metadata.MetadataManager}
 *
 * @author Ulises Bocchio
 */
@Data
public class MetadataManagerProperties {
    /**
     * Sets name of IDP to be used as default.
     */
    private String defaultIdp;

    /**
     * Sets nameId of SP hosted on this machine. This can either be called from springContext or automatically
     * during invocation of metadata generation filter.
     */
    private String hostedSpName;

    /**
     * Interval in milliseconds used for re-verification of metadata and their reload. Upon trigger each provider
     * is asked to return it's metadata, which might trigger their reloading. In case metadata is reloaded the
     * manager is notified and automatically refreshes all internal data by calling refreshMetadata.
     * <p>
     * In case the value is smaller than zero the timer is not created.
     * </p>
     */
    private Long refreshCheckInterval = -1L;
}
