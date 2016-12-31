package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

/**
 * {@link SingleLogoutProfileImpl} with non-required autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLSingleLogoutProfileImpl extends SingleLogoutProfileImpl {

    /**
     * Metadata manager provides information about all available IDP and SP entities.
     *
     * @param metadata metadata manager
     */
    @Override
    @Autowired(required = false)
    public void setMetadata(MetadataManager metadata) {
        super.setMetadata(metadata);
    }
}
