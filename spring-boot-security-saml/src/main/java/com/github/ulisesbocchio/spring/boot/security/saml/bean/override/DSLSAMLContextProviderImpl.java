package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;

/**
 * {@link SAMLContextProviderImpl} with non-required Autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLSAMLContextProviderImpl extends SAMLContextProviderImpl {


    /**
     * Key manager provides information about private certificate and trusted keys provide in addition to
     * cryptographic material present in entity metadata documents.
     *
     * @param keyManager key manager
     */
    @Override
    @Autowired(required = false)
    public void setKeyManager(KeyManager keyManager) {
        super.setKeyManager(keyManager);
    }

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
