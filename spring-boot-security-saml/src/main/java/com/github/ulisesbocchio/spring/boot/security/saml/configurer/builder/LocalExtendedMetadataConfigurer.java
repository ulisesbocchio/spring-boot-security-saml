package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.bean.override.LocalExtendedMetadata;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.saml.metadata.ExtendedMetadata;

/**
 * Builder configurer that takes care of configuring/customizing the {@link LocalExtendedMetadata} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link LocalExtendedMetadata} bean is defined, priority goes to a custom LocalExtendedMetadata provided explicitly
 * to this configurer through the constructor. And if not provided through the constructor, a default implementation is
 * instantiated that is configurable through the DSL methods.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getLocalExtendedMetadata()} if no custom Extended
 * Metadata is provided, for some DSL methods if they that are not used. In other words, the user is able to configure
 * the Extended Metadata for the local entity through the following properties:
 * <pre>
 *     saml.sso.local-extended-metadata.local
 *     saml.sso.local-extended-metadata.alias
 *     saml.sso.local-extended-metadata.idp-discovery-enabled
 *     saml.sso.local-extended-metadata.idp-discovery-url
 *     saml.sso.local-extended-metadata.idp-discovery-response-url
 *     saml.sso.local-extended-metadata.ecp-enabled
 *     saml.sso.local-extended-metadata.security-profile
 *     saml.sso.local-extended-metadata.ssl-security-profile
 *     saml.sso.local-extended-metadata.ssl-hostname-verification
 *     saml.sso.local-extended-metadata.signing-key
 *     saml.sso.local-extended-metadata.sign-metadata
 *     saml.sso.local-extended-metadata.key-info-generator-name
 *     saml.sso.local-extended-metadata.encryption-key
 *     saml.sso.local-extended-metadata.tls-key
 *     saml.sso.local-extended-metadata.trusted-keys
 *     saml.sso.local-extended-metadata.require-logout-request-signed
 *     saml.sso.local-extended-metadata.require-logout-response-signed
 *     saml.sso.local-extended-metadata.require-artifact-resolve-signed
 *     saml.sso.local-extended-metadata.support-unsolicited-response
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class LocalExtendedMetadataConfigurer extends ExtendedMetadataConfigurer {
    public LocalExtendedMetadataConfigurer() {
        local = true;
    }

    public LocalExtendedMetadataConfigurer(ExtendedMetadata extendedMetadata) {
        super(extendedMetadata);
    }

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        extendedMetadataBean = builder.getSharedObject(LocalExtendedMetadata.class);
        extendedMetadataConfig = builder.getSharedObject(SAMLSSOProperties.class).getLocalExtendedMetadata();
    }

    @Override
    protected ExtendedMetadata createExtendedMetadata() {
        return new LocalExtendedMetadata();
    }

    @Override
    protected void shareExtendedMetadata(ServiceProviderBuilder builder) {
        builder.setSharedObject(LocalExtendedMetadata.class, (LocalExtendedMetadata) extendedMetadata);
    }
}
