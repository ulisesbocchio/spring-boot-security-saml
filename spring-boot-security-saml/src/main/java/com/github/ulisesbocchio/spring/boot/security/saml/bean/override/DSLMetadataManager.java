package com.github.ulisesbocchio.spring.boot.security.saml.bean.override;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.List;

/**
 * {@link MetadataManager} with non-required autowire.
 *
 * @author Ulises Bocchio
 */
public class DSLMetadataManager extends MetadataManager {

    /**
     * Creates new metadata manager, automatically registers itself for notifications from metadata changes and calls
     * reload upon a change. Also registers timer which verifies whether metadata needs to be reloaded in a specified
     * time interval.
     * <p>
     * It is mandatory that method afterPropertiesSet is called after the construction.
     *
     * @param providers providers to include, mustn't be null or empty
     * @throws MetadataProviderException error during initialization
     */
    public DSLMetadataManager(List<MetadataProvider> providers) throws MetadataProviderException {
        super(providers);
    }

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
