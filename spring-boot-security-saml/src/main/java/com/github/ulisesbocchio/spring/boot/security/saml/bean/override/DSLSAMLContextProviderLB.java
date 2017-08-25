package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;

/**
 * /**
 * {@link SAMLContextProviderLB} with non-required Autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLSAMLContextProviderLB extends SAMLContextProviderLB {

    /**
     * {@inheritDoc}
     */
    @Override
    @Autowired(required = false)
    public void setKeyManager(KeyManager keyManager) {
        super.setKeyManager(keyManager);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Autowired(required = false)
    public void setMetadata(MetadataManager metadata) {
        super.setMetadata(metadata);
    }
}
