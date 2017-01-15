package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.security.saml.metadata.ExtendedMetadata;

/**
 * A Version of {@link ExtendedMetadata} for local metadata only.
 *
 * @author Ulises Bocchio
 */
public class LocalExtendedMetadata extends ExtendedMetadata {
    public LocalExtendedMetadata() {
        super.setLocal(true);
    }

    @Override
    public void setLocal(boolean local) {
        throw new IllegalStateException("This implementation is only for Local (SP) Metadata");
    }
}
