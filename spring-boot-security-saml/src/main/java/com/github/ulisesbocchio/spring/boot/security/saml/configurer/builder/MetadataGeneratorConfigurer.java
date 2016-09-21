package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilderResult;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.MetadataGeneratorProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.opensaml.saml2.metadata.EntityDescriptor;
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
 *     saml.sso.metadata-generator.metadata-url
 *     saml.sso.metadata-generator.entity-id
 *     saml.sso.metadata-generator.want-assertion-signed
 *     saml.sso.metadata-generator.request-signed
 *     saml.sso.metadata-generator.name-id
 *     saml.sso.metadata-generator.entity-base-url
 *     saml.sso.metadata-generator.bindings-sso
 *     saml.sso.metadata-generator.bindings-hok-sso
 *     saml.sso.metadata-generator.bindings-slo
 *     saml.sso.metadata-generator.assertion-consumer-index
 *     saml.sso.metadata-generator.include-discovery-extension
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class MetadataGeneratorConfigurer extends SecurityConfigurerAdapter<ServiceProviderBuilderResult, ServiceProviderBuilder> {

    private String metadataURL;
    private String entityId;
    private String id;
    private Boolean wantAssertionSigned;
    private Boolean requestSigned;
    private Collection<String> nameId;
    private String entityBaseURL;
    private Collection<String> bindingsHoKSSO;
    private Collection<String> bindingsSLO;
    private Collection<String> bindingsSSO;
    private Integer assertionConsumerIndex;
    private Boolean includeDiscoveryExtension;
    private MetadataGeneratorProperties config;
    private ServiceProviderEndpoints endpoints;
    private ExtendedMetadata extendedMetadata;
    private MetadataGenerator metadataGenerator;
    private MetadataGenerator metadataGeneratorBean;

    public MetadataGeneratorConfigurer() {
    }

    public MetadataGeneratorConfigurer(MetadataGenerator metadataGenerator) {
        this.metadataGenerator = metadataGenerator;
    }

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        config = builder.getSharedObject(SAMLSSOProperties.class).getMetadataGenerator();
        endpoints = builder.getSharedObject(ServiceProviderEndpoints.class);
        metadataGeneratorBean = builder.getSharedObject(MetadataGenerator.class);
    }

    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        extendedMetadata = builder.getSharedObject(ExtendedMetadata.class);
        MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
        metadataURL = Optional.ofNullable(metadataURL).orElseGet(config::getMetadataUrl);
        endpoints.setMetadataURL(metadataURL);
        metadataDisplayFilter.setFilterProcessesUrl(metadataURL);

        MetadataGenerator actualMetadataGenerator = metadataGeneratorBean;
        if(actualMetadataGenerator == null) {
            if(this.metadataGenerator != null) {
                actualMetadataGenerator = this.metadataGenerator;
            } else {
                actualMetadataGenerator = new MetadataGenerator();
            }
            actualMetadataGenerator.setEntityId(Optional.ofNullable(entityId).orElseGet(config::getEntityId));
            actualMetadataGenerator.setId(Optional.ofNullable(id).orElseGet(config::getId));
            actualMetadataGenerator.setExtendedMetadata(extendedMetadata);
            actualMetadataGenerator.setWantAssertionSigned(Optional.ofNullable(wantAssertionSigned).orElseGet(config::isWantAssertionSigned));
            actualMetadataGenerator.setRequestSigned(Optional.ofNullable(requestSigned).orElseGet(config::isRequestSigned));
            actualMetadataGenerator.setNameID(Optional.ofNullable(nameId).orElseGet(config::getNameId));
            actualMetadataGenerator.setEntityBaseURL(Optional.ofNullable(entityBaseURL).orElseGet(config::getEntityBaseUrl));
            actualMetadataGenerator.setBindingsHoKSSO(Optional.ofNullable(bindingsHoKSSO).orElseGet(config::getBindingsHokSso));
            actualMetadataGenerator.setBindingsSLO(Optional.ofNullable(bindingsSLO).orElseGet(config::getBindingsSlo));
            actualMetadataGenerator.setBindingsSSO(Optional.ofNullable(bindingsSSO).orElseGet(config::getBindingsSso));
            actualMetadataGenerator.setAssertionConsumerIndex(Optional.ofNullable(assertionConsumerIndex).orElseGet(config::getAssertionConsumerIndex));
            actualMetadataGenerator.setIncludeDiscoveryExtension(Optional.ofNullable(includeDiscoveryExtension).orElseGet(config::isIncludeDiscoveryExtension));
        }

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(actualMetadataGenerator);

        builder.setSharedObject(MetadataGenerator.class, actualMetadataGenerator);
        builder.setSharedObject(MetadataDisplayFilter.class, metadataDisplayFilter);
        builder.setSharedObject(MetadataGeneratorFilter.class, metadataGeneratorFilter);
    }

    /**
     * {@link MetadataDisplayFilter} processing URL. Defines which URL will display the Service Provider Metadata.
     * Default is {@code "/saml/metadata"}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadata-generator.metadata-url
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
     *      saml.sso.metadata-generator.entity-id
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
     * This Service Provider's SAML ID. Used as ID of {@link EntityDescriptor} managed by {@link MetadataGenerator}.
     * Default is {@code null}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadata-generator.id
     * </pre>
     * </p>
     *
     * @param id the id.
     * @return this configurer for further customization
     */
    public MetadataGeneratorConfigurer id(String id) {
        this.id = id;
        return this;
    }

    /**
     * Whether incoming SAML assertions should be signed or not.
     * Default is {@code true}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.metadata-generator.want-assertion-signed
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
     *      saml.sso.metadata-generator.request-signed
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
     *      saml.sso.metadata-generator.name-id
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
     *      saml.sso.metadata-generator.entity-base-url
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
     *      saml.sso.metadata-generator.bindings-hok-sso
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
     *      saml.sso.metadata-generator.bindings-slo
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
     *      saml.sso.metadata-generator.bindings-sso
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
     *      saml.sso.metadata-generator.assertion-consumer-index
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
     *      saml.sso.metadata-generator.include-discovery-extension
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
