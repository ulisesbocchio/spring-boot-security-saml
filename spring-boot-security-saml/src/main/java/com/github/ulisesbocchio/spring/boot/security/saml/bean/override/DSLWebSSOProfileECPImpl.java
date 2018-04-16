package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;

/**
 * {@link WebSSOProfileECPImpl} with non-required autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLWebSSOProfileECPImpl extends WebSSOProfileECPImpl {

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

	@Override
	public void afterPropertiesSet() throws Exception {
		// org.springframework.security.saml.websso.AbstractProfileBase.afterPropertiesSet()
		// will check that properties are set, which is not desirable here
		// as that defeats the purpose of the non-required autowire intent of this class.
	}
}
