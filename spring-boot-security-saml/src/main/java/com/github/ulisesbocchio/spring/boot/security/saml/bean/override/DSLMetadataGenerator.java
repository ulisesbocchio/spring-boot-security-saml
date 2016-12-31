package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataGenerator;

/**
 * {@link MetadataGenerator} with non-required autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLMetadataGenerator extends MetadataGenerator {

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
}
