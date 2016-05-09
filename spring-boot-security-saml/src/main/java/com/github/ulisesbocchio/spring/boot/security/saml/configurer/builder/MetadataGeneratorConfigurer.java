package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

/**
 * <p>
 * Builder configurer that takes care of configuring/customizing the {@link MetadataGenerator},
 * {@link MetadataDisplayFilter}, and {@link MetadataGeneratorFilter} bean.
 * </p>
 * <p>
 * This configurer always instantiates its own {@link MetadataGenerator},
 * {@link MetadataDisplayFilter}, and {@link MetadataGeneratorFilter}  based on the specified configuration.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getMetadataGenerator()} for some DSL methods if
 * they are not used. In other words, the user is able to configure the filters through the following properties:
 * <pre>
 *     saml.sso.metadataGenerator.metadataURL
 *     saml.sso.metadataGenerator.entityId
 *     saml.sso.metadataGenerator.wantAssertionSigned
 *     saml.sso.metadataGenerator.requestSigned
 *     saml.sso.metadataGenerator.nameId
 *     saml.sso.metadataGenerator.entityBaseURL
 *     saml.sso.metadataGenerator.bindingsSSO
 *     saml.sso.metadataGenerator.bindingsHoKSSO
 *     saml.sso.metadataGenerator.bindingsSLO
 *     saml.sso.metadataGenerator.assertionConsumerIndex
 *     saml.sso.metadataGenerator.includeDiscoveryExtension
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class MetadataGeneratorConfigurer extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder> {

    private String metadataURL;
    private String entityId;
    private Boolean wantAssertionSigned;
    private Boolean requestSigned;
    private Collection<String> nameId;
    private String entityBaseURL;
    private Collection<String> bindingsHoKSSO;
    private Collection<String> bindingsSLO;
    private Collection<String> bindingsSSO;
    private Integer assertionConsumerIndex;
    private Boolean includeDiscoveryExtension;
    private SAMLSSOProperties.MetadataGeneratorConfiguration config;
    private ServiceProviderEndpoints endpoints;
    private ExtendedMetadata extendedMetadata;

    @Override
    public void init(ServiceProviderSecurityBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getMetadataGenerator();
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
    }

    @Override
    public void configure(ServiceProviderSecurityBuilder builder) throws Exception {
        extendedMetadata = builder.getSharedObject(ExtendedMetadata.class);
        MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
        metadataURL = Optional.ofNullable(metadataURL).orElseGet(config::getMetadataURL);
        endpoints.setMetadataURL(metadataURL);
        metadataDisplayFilter.setFilterProcessesUrl(metadataURL);

        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(Optional.ofNullable(entityId).orElseGet(config::getEntityId));
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        metadataGenerator.setWantAssertionSigned(Optional.ofNullable(wantAssertionSigned).orElseGet(config::isWantAssertionSigned));
        metadataGenerator.setRequestSigned(Optional.ofNullable(requestSigned).orElseGet(config::isRequestSigned));
        metadataGenerator.setNameID(Optional.ofNullable(nameId).orElseGet(config::getNameId));
        metadataGenerator.setEntityBaseURL(Optional.ofNullable(entityBaseURL).orElseGet(config::getEntityBaseURL));
        metadataGenerator.setBindingsHoKSSO(Optional.ofNullable(bindingsHoKSSO).orElseGet(config::getBindingsHoKSSO));
        metadataGenerator.setBindingsSLO(Optional.ofNullable(bindingsSLO).orElseGet(config::getBindingsSLO));
        metadataGenerator.setBindingsSSO(Optional.ofNullable(bindingsSSO).orElseGet(config::getBindingsSSO));
        metadataGenerator.setAssertionConsumerIndex(Optional.ofNullable(assertionConsumerIndex).orElseGet(config::getAssertionConsumerIndex));
        metadataGenerator.setIncludeDiscoveryExtension(Optional.ofNullable(includeDiscoveryExtension).orElseGet(config::isIncludeDiscoveryExtension));

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(metadataGenerator);

        builder.setSharedObject(MetadataGenerator.class, metadataGenerator);
        builder.setSharedObject(MetadataDisplayFilter.class, metadataDisplayFilter);
        builder.setSharedObject(MetadataGeneratorFilter.class, metadataGeneratorFilter);
    }

    /**
     * {@link MetadataDisplayFilter} processing URL. Defines which URL will display the Service Provider Metadata.
     * Default is {@code "/saml/metadata"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.metadataURL
     * </pre>
     * </p>
     *
     * @param metadataURL the metadata display filter processing URL.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer metadataURL(String metadataURL) {
        this.metadataURL = metadataURL;
        return this;
    }

    /**
     * This Service Provider's SAML Entity ID. Used as entity id for generated requests from this Service Provider.
     * Default is {@code "localhost"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.entityId
     * </pre>
     * </p>
     *
     * @param entityId the entity id of this Service Provider.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer entityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    /**
     * Whether incoming SAML assertions should be signed or not.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.wantAssertionSigned
     * </pre>
     * </p>
     *
     * @param wantAssertionSigned true if assertions are wanted signed.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer wantAssertionSigned(Boolean wantAssertionSigned) {
        this.wantAssertionSigned = wantAssertionSigned;
        return this;
    }

    /**
     * Whether Authentication Requests should be signed by this Service Provider or not.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.requestSigned
     * </pre>
     * </p>
     *
     * @param requestSigned true if authentication requests should be signed.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer requestSigned(Boolean requestSigned) {
        this.requestSigned = requestSigned;
        return this;
    }

    /**
     * NameIDs to be included in generated metadata.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.nameId
     * </pre>
     * </p>
     *
     * @param nameId the name IDs to be included in generated metadata.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer nameId(String... nameId) {
        this.nameId = Arrays.asList(nameId);
        return this;
    }

    /**
     * This Service Provider's entity base URL. Provide if base URL cannot be inferred by using the hostname where
     * the Service Provider will be running. I.E. if running on the cloud behind a load balancer.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.entityBaseURL
     * </pre>
     * </p>
     *
     * @param entityBaseURL the Service Provider base URL.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer entityBaseURL(String entityBaseURL) {
        this.entityBaseURL = entityBaseURL;
        return this;
    }

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On Holder of Key. Ordering of
     * bindings affects inclusion in the generated metadata. Supported values are: "artifact" (or
     * "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") and "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").
     * By default there are no included bindings for the profile.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.bindingsHoKSSO
     * </pre>
     * </p>
     *
     * @param bindingsHoKSSO bindings for web single sign-on holder-of-key
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer bindingsHoKSSO(String... bindingsHoKSSO) {
        this.bindingsHoKSSO = Arrays.asList(bindingsHoKSSO);
        return this;
    }

    /**
     * List of bindings to be included in the generated metadata for Single Logout. Ordering of bindings affects
     * inclusion in the generated metadata. Supported values are: "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
     * and "redirect" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"). The following bindings are included by
     * default: "post", "redirect".
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.bindingsSLO
     * </pre>
     * </p>
     *
     * @param bindingsSLO bindings for single logout
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer bindingsSLO(String... bindingsSLO) {
        this.bindingsSLO = Arrays.asList(bindingsSLO);
        return this;
    }

    /**
     * List of bindings to be included in the generated metadata for Web Single Sign-On. Ordering of bindings affects
     * inclusion in the generated metadata. Supported values are: "artifact" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"),
     * "post" (or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") and "paos" (or "urn:oasis:names:tc:SAML:2.0:bindings:PAOS").
     * The following bindings are included by default: "artifact", "post".
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.bindingsSSO
     * </pre>
     * </p>
     *
     * @param bindingsSSO bindings for web single sign-on
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer bindingsSSO(String... bindingsSSO) {
        this.bindingsSSO = Arrays.asList(bindingsSSO);
        return this;
    }

    /**
     * Generated assertion consumer service with the index equaling set value will be marked as default. Use negative
     * value to skip the default attribute altogether.
     * Default is {@code 0}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.assertionConsumerIndex
     * </pre>
     * </p>
     *
     * @param assertionConsumerIndex assertion consumer index of service to mark as default
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer assertionConsumerIndex(Integer assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
        return this;
    }

    /**
     * When true discovery profile extension metadata pointing to the default SAMLEntryPoint will be generated and
     * stored in the generated metadata document.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadataGenerator.includeDiscoveryExtension
     * </pre>
     * </p>
     *
     * @param includeDiscoveryExtension flag indicating whether IDP discovery should be enabled
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer includeDiscoveryExtension(Boolean includeDiscoveryExtension) {
        this.includeDiscoveryExtension = includeDiscoveryExtension;
        return this;
    }
}
