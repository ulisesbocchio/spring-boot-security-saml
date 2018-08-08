package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.bean.override.DSLSAMLContextProviderImpl;
import com.github.ulisesbocchio.spring.boot.security.saml.bean.override.DSLSAMLContextProviderLB;
import com.github.ulisesbocchio.spring.boot.security.saml.bean.override.LocalExtendedMetadata;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder.*;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.CheckedConsumer;
import lombok.SneakyThrows;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.websso.*;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Class for internal usage of this Spring Boot Plugin. It deals with all the nitty-gritty of wiring all required
 * Spring Security SAML beans, while also exposing most aspects of its configuration through 2 different methods:
 * <ul>
 * <li>Custom Beans</li>
 * <li>A java DSL using Spring Security's builder classes</li>
 * <li>Exposed configuration properties through {@link SAMLSSOProperties}</li>
 * </ul>
 * all three methods can be used exclusively or mixed. Explicit Bean Definition always takes precedence. Explicit
 * configuration through the DSL always takes precedence over the properties. Most options provide configuration
 * overrides by specifying a Bean of certain type, but not everything. Check with the Javadoc of each method for
 * further details.
 *
 * @author Ulises Bocchio
 */
public class ServiceProviderBuilder extends
        AbstractConfiguredSecurityBuilder<Void, ServiceProviderBuilder> {

    public ServiceProviderBuilder() {
        super(new ObjectPostProcessor<Object>() {
            @Override
            public <T> T postProcess(T object) {
                return object;
            }
        }, false);
    }

    @Override
    public <C> void setSharedObject(Class<C> sharedType, C object) {
        if (object != null) {
            super.setSharedObject(sharedType, object);
        }
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    private <C extends SecurityConfigurerAdapter<Void, ServiceProviderBuilder>> C getOrApply(
            C configurer) {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    private <C extends SecurityConfigurerAdapter<Void, ServiceProviderBuilder>> void reApply(C configurer) {
        C existing = (C) removeConfigurer(configurer.getClass());
        apply(existing);
    }

    @Override
    protected void beforeInit() throws Exception {
        //All configurers are initialized only once.
        //Order of configurers is established by the following stream.
        boolean lbEnabled = getSharedObject(SAMLSSOProperties.class).getContextProvider().getLb().isEnabled();
        Stream.of(keyManager(),
                tls(),
                extendedMetadata(),
                localExtendedMetadata(),
                metadataManager(),
                authenticationProvider(),
                (lbEnabled ? samlContextProviderLb() : samlContextProvider()),
                samlProcessor(),
                ssoProfileConsumer(),
                hokProfileConsumer(),
                ssoProfile(),
                ecpProfile(),
                hokProfile(),
                sloProfile(),
                logout(),
                sso(),
                metadataGenerator())
                .forEach(this::reApply);
    }

    @Override
    protected Void performBuild() throws Exception {
        KeyManager keyManager = getSharedObject(KeyManager.class);
        MetadataManager metadataManager = getSharedObject(MetadataManager.class);
        SAMLContextProvider samlContextProvider = getSharedObject(SAMLContextProvider.class);
        SAMLProcessor samlProcessor = getSharedObject(SAMLProcessor.class);
        WebSSOProfileConsumer webSSOprofileConsumer = getSharedObject(WebSSOProfileConsumer.class);
        WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer = getSharedObject(WebSSOProfileConsumerHoKImpl.class);
        WebSSOProfile webSSOProfile = getSharedObject(WebSSOProfile.class);
        WebSSOProfileECPImpl ecpProfile = getSharedObject(WebSSOProfileECPImpl.class);
        WebSSOProfileHoKImpl hokWebSSOProfile = getSharedObject(WebSSOProfileHoKImpl.class);
        SingleLogoutProfile sloProfile = getSharedObject(SingleLogoutProfile.class);
        MetadataGenerator metadataGenerator = getSharedObject(MetadataGenerator.class);
        SAMLAuthenticationProvider authenticationProvider = getSharedObject(SAMLAuthenticationProvider.class);
        SAMLLogoutFilter samlLogoutFilter = getSharedObject(SAMLLogoutFilter.class);
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = getSharedObject(SAMLLogoutProcessingFilter.class);
        MetadataDisplayFilter metadataDisplayFilter = getSharedObject(MetadataDisplayFilter.class);
        MetadataGeneratorFilter metadataGeneratorFilter = getSharedObject(MetadataGeneratorFilter.class);
        SAMLProcessingFilter sAMLProcessingFilter = getSharedObject(SAMLProcessingFilter.class);
        SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter = getSharedObject(SAMLWebSSOHoKProcessingFilter.class);
        SAMLDiscovery sAMLDiscovery = getSharedObject(SAMLDiscovery.class);
        SAMLEntryPoint sAMLEntryPoint = getSharedObject(SAMLEntryPoint.class);
        TLSProtocolConfigurer tlsProtocolConfigurer = getSharedObject(TLSProtocolConfigurer.class);
        SAMLLogger samlLogger = getSharedObject(SAMLLogger.class);
        ArtifactResolutionProfile artifactProfile = getSharedObject(ArtifactResolutionProfile.class);

        metadataManager.setKeyManager(keyManager);
        metadataManager.setTLSConfigurer(tlsProtocolConfigurer);
        metadataManager.setRefreshRequired(true);
        metadataManager.afterPropertiesSet();

        if (samlContextProvider instanceof SAMLContextProviderImpl) {
            SAMLContextProviderImpl impl = (SAMLContextProviderImpl) samlContextProvider;
            impl.setKeyManager(keyManager);
            impl.setMetadata(metadataManager);
            impl.afterPropertiesSet();
        }

        maybePopulateBaseProfile(webSSOprofileConsumer, metadataManager, samlProcessor);

        maybePopulateBaseProfile(hokWebSSOprofileConsumer, metadataManager, samlProcessor);

        maybePopulateBaseProfile(webSSOProfile, metadataManager, samlProcessor);

        maybePopulateBaseProfile(ecpProfile, metadataManager, samlProcessor);

        maybePopulateBaseProfile(hokWebSSOProfile, metadataManager, samlProcessor);

        maybePopulateBaseProfile(sloProfile, metadataManager, samlProcessor);

        maybePopulateBaseProfile(artifactProfile, metadataManager, samlProcessor);

        metadataGenerator.setSamlWebSSOFilter(sAMLProcessingFilter);
        metadataGenerator.setSamlWebSSOHoKFilter(sAMLWebSSOHoKProcessingFilter);
        metadataGenerator.setSamlLogoutProcessingFilter(samlLogoutProcessingFilter);
        metadataGenerator.setSamlEntryPoint(sAMLEntryPoint);
        metadataGenerator.setKeyManager(keyManager);

        authenticationProvider.setSamlLogger(samlLogger);
        authenticationProvider.setConsumer(webSSOprofileConsumer);
        authenticationProvider.setHokConsumer(hokWebSSOprofileConsumer);
        authenticationProvider.afterPropertiesSet();

        samlLogoutFilter.setSamlLogger(samlLogger);
        samlLogoutFilter.setProfile(sloProfile);
        samlLogoutFilter.setContextProvider(samlContextProvider);
        samlLogoutFilter.afterPropertiesSet();

        samlLogoutProcessingFilter.setSamlLogger(samlLogger);
        samlLogoutProcessingFilter.setSAMLProcessor(samlProcessor);
        samlLogoutProcessingFilter.setLogoutProfile(sloProfile);
        samlLogoutProcessingFilter.setContextProvider(samlContextProvider);
        samlLogoutProcessingFilter.afterPropertiesSet();

        metadataDisplayFilter.setKeyManager(keyManager);
        metadataDisplayFilter.setManager(metadataManager);
        metadataDisplayFilter.setContextProvider(samlContextProvider);
        metadataDisplayFilter.afterPropertiesSet();

        metadataGeneratorFilter.setManager(metadataManager);
        metadataGeneratorFilter.setDisplayFilter(metadataDisplayFilter);
        metadataGeneratorFilter.afterPropertiesSet();

        sAMLProcessingFilter.setSAMLProcessor(samlProcessor);
        sAMLProcessingFilter.setContextProvider(samlContextProvider);
        sAMLProcessingFilter.afterPropertiesSet();

        if (sAMLWebSSOHoKProcessingFilter != null) {
            sAMLWebSSOHoKProcessingFilter.setSAMLProcessor(samlProcessor);
            sAMLWebSSOHoKProcessingFilter.setContextProvider(samlContextProvider);
            sAMLWebSSOHoKProcessingFilter.afterPropertiesSet();
        }

        sAMLDiscovery.setMetadata(metadataManager);
        sAMLDiscovery.setSamlEntryPoint(sAMLEntryPoint);
        sAMLDiscovery.setContextProvider(samlContextProvider);
        sAMLDiscovery.afterPropertiesSet();

        sAMLEntryPoint.setWebSSOprofile(webSSOProfile);
        sAMLEntryPoint.setWebSSOprofileECP(ecpProfile);
        sAMLEntryPoint.setWebSSOprofileHoK(hokWebSSOProfile);
        sAMLEntryPoint.setSamlLogger(samlLogger);
        sAMLEntryPoint.setSamlDiscovery(sAMLDiscovery);
        sAMLEntryPoint.setContextProvider(samlContextProvider);
        sAMLEntryPoint.setMetadata(metadataManager);
        sAMLEntryPoint.afterPropertiesSet();

        return null;
    }

    @SneakyThrows
    private void maybePopulateBaseProfile(Object obj, MetadataManager metadataManager, SAMLProcessor samlProcessor) {
        if (obj instanceof AbstractProfileBase) {
            AbstractProfileBase impl = (AbstractProfileBase) obj;
            impl.setMetadata(metadataManager);
            impl.setProcessor(samlProcessor);
            impl.afterPropertiesSet();
        }
    }

    /**
     * Returns a {@link SAMLContextProviderConfigurer} for customization of the {@link SAMLContextProvider} default
     * implementation {@link SAMLContextProviderImpl}. Either use this method or {@link
     * #samlContextProvider(SAMLContextProvider)}.
     * Alternatively define a {@link DSLSAMLContextProviderImpl} bean.
     * <p>
     * The Context Provider is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP)
     * is responsible for its handling.
     * </p>
     *
     * @return the {@link SAMLContextProvider} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SAMLContextProviderConfigurer samlContextProvider() {
        return getOrApply(new SAMLContextProviderConfigurer());
    }

    /**
     * Provide a specific {@link SAMLContextProvider}. Either use this method or {@link #samlContextProvider()}.
     * Alternatively define a {@link DSLSAMLContextProviderImpl} bean.
     * <p>
     * The Context Provider is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP)
     * is responsible for its handling.
     * </p>
     *
     * @param samlContextProvider the context provider to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder samlContextProvider(SAMLContextProvider samlContextProvider) {
        getOrApply(new SAMLContextProviderConfigurer(samlContextProvider));
        return this;
    }

    /**
     * Returns a {@link SAMLContextProviderLBConfigurer} for customization of the {@link SAMLContextProvider} default
     * implementation {@link SAMLContextProviderLB}. Either use this method or {@link
     * #samlContextProviderLb(SAMLContextProviderLB)}.
     * Alternatively define a {@link DSLSAMLContextProviderLB} bean.
     * <p>
     * The Context Provider is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP)
     * is responsible for its handling.
     * </p>
     *
     * @return the {@link SAMLContextProviderLB} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SAMLContextProviderLBConfigurer samlContextProviderLb() {
        removeConfigurer(SAMLContextProviderConfigurer.class);
        return getOrApply(new SAMLContextProviderLBConfigurer());
    }

    /**
     * Provide a specific {@link SAMLContextProviderLB}. Either use this method or {@link #samlContextProvider()}.
     * Alternatively define a {@link DSLSAMLContextProviderLB} bean.
     * <p>
     * The Context Provider is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP)
     * is responsible for its handling.
     * </p>
     *
     * @param samlContextProviderLb the context provider to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder samlContextProviderLb(SAMLContextProviderLB samlContextProviderLb) {
        removeConfigurer(SAMLContextProviderConfigurer.class);
        getOrApply(new SAMLContextProviderLBConfigurer(samlContextProviderLb));
        return this;
    }

    /**
     * Returns a {@link MetadataManagerConfigurer} for customization of the {@link MetadataManager} default
     * implementation {@link CachingMetadataManager}. Either use this method or {@link
     * #metadataManager(MetadataManager)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getMetadataManager()} and {@link
     * SAMLSSOProperties#getExtendedDelegate()}.
     * Alternatively define a {@link MetadataManager} bean.
     * <p>
     * Metadata Manager keeps track of all available identity and service providers configured inside the chained
     * metadata providers. Exactly one service provider can be determined as hosted.
     * </p>
     *
     * @return the {@link MetadataManager} configurer.
     * @throws Exception Any exception during configuration.
     */
    public MetadataManagerConfigurer metadataManager() {
        return getOrApply(new MetadataManagerConfigurer());
    }

    /**
     * Provide a specific {@link MetadataManager}. Either use this method or {@link #metadataManager()}.
     * Alternatively define a {@link MetadataManager} bean.
     * <p>
     * Metadata Manager keeps track of all available identity and service providers configured inside the chained
     * metadata providers. Exactly one service provider can be determined as hosted.
     * </p>
     *
     * @param metadataManager the metadata Manager to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder metadataManager(MetadataManager metadataManager) {
        getOrApply(new MetadataManagerConfigurer(metadataManager));
        return this;
    }

    /**
     * Returns a {@link KeyManagerConfigurer} for customization of the {@link KeyManager} default
     * implementation {@link JKSKeyManager}. Either use this method or {@link #keyManager(KeyManager)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getKeyManager()}.
     * Alternatively define a {@link KeyManager} bean.
     * <p>
     * KeyManager provides access to private and trusted keys for SAML Extension configuration. Keys are stored in the
     * underlying KeyStore object.
     * </p>
     *
     * @return the {@link KeyManager} configurer.
     * @throws Exception Any exception during configuration.
     */
    public KeyManagerConfigurer keyManager() {
        return getOrApply(new KeyManagerConfigurer());
    }

    /**
     * Provide a specific {@link KeyManager}. Either use this method or {@link #keyManager()}.
     * Alternatively define a {@link KeyManager} bean.
     * <p>
     * KeyManager provides access to private and trusted keys for SAML Extension configuration. Keys are stored in the
     * underlying KeyStore object.
     * </p>
     *
     * @param keyManager the key Manager to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder keyManager(KeyManager keyManager) {
        getOrApply(new KeyManagerConfigurer(keyManager));
        return this;
    }

    /**
     * Returns a {@link SAMLProcessorConfigurer} for customization of the {@link SAMLProcessor} default
     * implementation {@link SAMLProcessorImpl}. Either use this method or {@link #samlProcessor(SAMLProcessor)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getSamlProcessor()}.
     * Alternatively define a {@link SAMLProcessor} bean.
     * <p>
     * SAML Processor is capable of parsing SAML message from HttpServletRequest and populate the SAMLMessageContext
     * for further validations.
     * </p>
     *
     * @return the {@link SAMLProcessor} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SAMLProcessorConfigurer samlProcessor() {
        return getOrApply(new SAMLProcessorConfigurer());
    }

    /**
     * Provide a specific {@link SAMLProcessor}. Either use this method or {@link #samlProcessor()}.
     * Alternatively define a {@link SAMLProcessor} bean.
     * <p>
     * SAML Processor is capable of parsing SAML message from HttpServletRequest and populate the SAMLMessageContext
     * for further validations.
     * </p>
     *
     * @param samlProcessor the saml Processor to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder samlProcessor(SAMLProcessor samlProcessor) {
        getOrApply(new SAMLProcessorConfigurer(samlProcessor));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileConsumerConfigurer} for customization of the {@link WebSSOProfileConsumer} default
     * implementation {@link WebSSOProfileConsumerImpl}. Either use this method or {@link
     * #ssoProfileConsumer(WebSSOProfileConsumer)}.
     * Alternatively define a {@link WebSSOProfileConsumer} bean with name webSSOprofileConsumer.
     * <p>
     * Web SSO Profile Consumer is able to process Response objects returned from the IDP after SP initialized SSO or
     * unsolicited response from IDP. In case the response is correctly validated and no errors are found the
     * SAMLCredential is created.
     * </p>
     *
     * @return the {@link WebSSOProfileConsumer} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileConsumerConfigurer ssoProfileConsumer() {
        return getOrApply(new WebSSOProfileConsumerConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileConsumer}. Either use this method or {@link #ssoProfileConsumer()}.
     * Alternatively define a {@link WebSSOProfileConsumer} bean with name webSSOprofileConsumer.
     * <p>
     * Web SSO Profile Consumer is able to process Response objects returned from the IDP after SP initialized SSO or
     * unsolicited response from IDP. In case the response is correctly validated and no errors are found the
     * SAMLCredential is created.
     * </p>
     *
     * @param ssoProfileConsumer the sso Profile Consumer to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder ssoProfileConsumer(WebSSOProfileConsumer ssoProfileConsumer) {
        getOrApply(new WebSSOProfileConsumerConfigurer(ssoProfileConsumer));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileHoKConsumerConfigurer} for customization of the {@link
     * WebSSOProfileConsumerHoKImpl} default
     * implementation {@link WebSSOProfileConsumerHoKImpl}. Either use this method or {@link
     * #hokProfileConsumer(WebSSOProfileConsumerHoKImpl)}.
     * Alternatively define a {@link WebSSOProfileConsumerHoKImpl} bean with name hokWebSSOprofileConsumer.
     * <p>
     * Web SSO Profile Consumer HOK implements processing of the SAML Holder-of-Key Browser SSO profile as per
     * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf.
     * </p>
     *
     * @return the {@link WebSSOProfileConsumerHoKImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileHoKConsumerConfigurer hokProfileConsumer() {
        return getOrApply(new WebSSOProfileHoKConsumerConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileConsumerHoKImpl}. Either use this method or {@link
     * #hokProfileConsumer()}.
     * Alternatively define a {@link WebSSOProfileConsumerHoKImpl} bean with name hokWebSSOprofileConsumer.
     * <p>
     * Web SSO Profile Consumer HOK implements processing of the SAML Holder-of-Key Browser SSO profile as per
     * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf.
     * </p>
     *
     * @param hokProfileConsumer the hok Profile Consumer to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder hokProfileConsumer(WebSSOProfileConsumerHoKImpl hokProfileConsumer) {
        getOrApply(new WebSSOProfileHoKConsumerConfigurer(hokProfileConsumer));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileConfigurer} for customization of the {@link WebSSOProfile} default
     * implementation {@link WebSSOProfileImpl}. Either use this method or {@link #ssoProfile(WebSSOProfile)}.
     * Alternatively define a {@link WebSSOProfile} bean with name webSSOprofile.
     * <p>
     * Web SSO Profile implements WebSSO profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
     * </p>
     *
     * @return the {@link WebSSOProfile} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileConfigurer ssoProfile() {
        return getOrApply(new WebSSOProfileConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfile}. Either use this method or {@link #ssoProfile()}.
     * Alternatively define a {@link WebSSOProfile} bean with name webSSOprofile.
     * <p>
     * Web SSO Profile implements WebSSO profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
     * </p>
     *
     * @param ssoProfile the sso Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder ssoProfile(WebSSOProfile ssoProfile) {
        getOrApply(new WebSSOProfileConfigurer(ssoProfile));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileECPConfigurer} for customization of the {@link WebSSOProfileECPImpl} default
     * implementation {@link WebSSOProfileECPImpl}. Either use this method or {@link
     * #ecpProfile(WebSSOProfileECPImpl)}.
     * Alternatively define a {@link WebSSOProfileECPImpl} bean with name ecpProfile.
     * <p>
     * Profile that implements the SAML ECP Profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. PAOS Binding is supported.
     * </p>
     *
     * @return the {@link WebSSOProfileECPImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileECPConfigurer ecpProfile() {
        return getOrApply(new WebSSOProfileECPConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileECPImpl}. Either use this method or {@link #ecpProfile()}.
     * Alternatively define a {@link WebSSOProfileECPImpl} bean with name ecpProfile.
     * <p>
     * Profile that implements the SAML ECP Profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. PAOS Binding is supported.
     * </p>
     *
     * @param ecpProfile the ecp Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder ecpProfile(WebSSOProfileECPImpl ecpProfile) {
        getOrApply(new WebSSOProfileECPConfigurer(ecpProfile));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileHoKConfigurer} for customization of the {@link WebSSOProfileHoKImpl} default
     * implementation {@link WebSSOProfileHoKImpl}. Either use this method or {@link
     * #hokProfile(WebSSOProfileHoKImpl)}.
     * Alternatively define a {@link WebSSOProfileHoKImpl} bean with name hokWebSSOProfile.
     * <p>
     * Profile that implements WebSSO profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
     * </p>
     *
     * @return the {@link WebSSOProfileHoKImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileHoKConfigurer hokProfile() {
        return getOrApply(new WebSSOProfileHoKConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileHoKImpl}. Either use this method or {@link #hokProfile()}.
     * Alternatively define a {@link WebSSOProfileHoKImpl} bean with name hokWebSSOProfile.
     * <p>
     * Profile that implements WebSSO profile and offers capabilities for SP initialized SSO and process Response
     * coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
     * </p>
     *
     * @param hokProfile the hok Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder hokProfile(WebSSOProfileHoKImpl hokProfile) {
        getOrApply(new WebSSOProfileHoKConfigurer(hokProfile));
        return this;
    }

    /**
     * Returns a {@link SingleLogoutProfileConfigurer} for customization of the {@link SingleLogoutProfile} default
     * implementation {@link SingleLogoutProfileImpl}. Either use this method or {@link
     * #sloProfile(SingleLogoutProfile)}.
     * Alternatively define a {@link SingleLogoutProfile} bean.
     * <p>
     * SLO Profile provides SAML Single Logout functionality according to SAML 2.0 Profiles specification.
     * </p>
     *
     * @return the {@link SingleLogoutProfileImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SingleLogoutProfileConfigurer sloProfile() {
        return getOrApply(new SingleLogoutProfileConfigurer());
    }

    /**
     * Provide a specific {@link SingleLogoutProfile}. Either use this method or {@link #sloProfile()}.
     * Alternatively define a {@link SingleLogoutProfile} bean.
     * <p>
     * SLO Profile provides SAML Single Logout functionality according to SAML 2.0 Profiles specification.
     * </p>
     *
     * @param sloProfile the slo Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder sloProfile(SingleLogoutProfile sloProfile) {
        getOrApply(new SingleLogoutProfileConfigurer(sloProfile));
        return this;
    }

    /**
     * Returns a {@link ExtendedMetadataConfigurer} for customization of the {@link ExtendedMetadata} default
     * implementation. Either use this method or {@link #extendedMetadata(ExtendedMetadata)}.
     * Alternatively define a {@link ExtendedMetadata} bean.
     * <p>
     * Extended Metadata contains additional information describing a SAML entity. This Metadata is only for remote
     * entities (the ones user can interact with like IDPs).
     * </p>
     *
     * @return the {@link ExtendedMetadata} configurer.
     * @throws Exception Any exception during configuration.
     */
    public ExtendedMetadataConfigurer extendedMetadata() {
        return getOrApply(new ExtendedMetadataConfigurer());
    }

    /**
     * Returns a {@link ExtendedMetadataConfigurer} for customization of the {@link LocalExtendedMetadata} default.
     * Either use this method or {@link #localExtendedMetadata(LocalExtendedMetadata)}.
     * Alternatively define a {@link LocalExtendedMetadata} bean.
     * <p>
     * Extended Metadata contains additional information describing a SAML entity. This metadata is for local
     * entities (the ones accessible as part of the deployed application using the SAML Extension).
     * </p>
     *
     * @return the {@link LocalExtendedMetadataConfigurer} configurer.
     * @throws Exception Any exception during configuration.
     */
    public LocalExtendedMetadataConfigurer localExtendedMetadata() {
        return getOrApply(new LocalExtendedMetadataConfigurer());
    }

    /**
     * Provide a specific {@link ExtendedMetadata}. Either use this method or {@link #extendedMetadata()}.
     * Alternatively define a {@link ExtendedMetadata} bean.
     * <p>
     * Extended Metadata contains additional information describing a SAML entity. This Metadata is only for remote
     * entities (the ones user can interact with like IDPs).
     * </p>
     *
     * @param extendedMetadata the extended Metadata to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder extendedMetadata(ExtendedMetadata extendedMetadata) {
        getOrApply(new ExtendedMetadataConfigurer(extendedMetadata));
        return this;
    }

    /**
     * Provide a specific {@link LocalExtendedMetadata}. Either use this method or {@link #localExtendedMetadata()}.
     * Alternatively define a {@link LocalExtendedMetadata} bean.
     * <p>
     * Extended Metadata contains additional information describing a SAML entity. This metadata is for local
     * entities (the ones accessible as part of the deployed application using the SAML Extension).
     * </p>
     *
     * @param extendedMetadata the extended Metadata to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder localExtendedMetadata(LocalExtendedMetadata extendedMetadata) {
        getOrApply(new ExtendedMetadataConfigurer(extendedMetadata));
        return this;
    }

    /**
     * Returns a {@link AuthenticationProviderConfigurer} for customization of the {@link SAMLAuthenticationProvider}
     * default
     * implementation {@link SAMLAuthenticationProvider}. Either use this method or {@link
     * #authenticationProvider(SAMLAuthenticationProvider)}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getAuthenticationProvider()}.
     * Alternatively define a {@link SAMLAuthenticationProvider} bean.
     * <p>
     * SAML Authentication provider is capable of verifying validity of a SAMLAuthenticationToken and in case the token
     * is valid to create an authenticated UsernamePasswordAuthenticationToken.
     * </p>
     *
     * @return the {@link SAMLAuthenticationProvider} configurer.
     * @throws Exception Any exception during configuration.
     */
    public AuthenticationProviderConfigurer authenticationProvider() {
        return getOrApply(new AuthenticationProviderConfigurer());
    }

    /**
     * Provide a specific {@link SAMLAuthenticationProvider}. Either use this method or {@link
     * #authenticationProvider()}.
     * Alternatively define a {@link SAMLAuthenticationProvider} bean.
     * <p>
     * SAML Authentication provider is capable of verifying validity of a SAMLAuthenticationToken and in case the token
     * is valid to create an authenticated UsernamePasswordAuthenticationToken.
     * </p>
     *
     * @param provider the authentication Provider to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderBuilder authenticationProvider(SAMLAuthenticationProvider provider) {
        getOrApply(new AuthenticationProviderConfigurer(provider));
        return this;
    }

    /**
     * Returns a {@link LogoutConfigurer} for customization of the {@link SAMLLogoutFilter} and
     * {@link SAMLProcessingFilter}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getLogout()}.
     *
     * @return the {@link LogoutConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public LogoutConfigurer logout() {
        return getOrApply(new LogoutConfigurer());
    }

    /**
     * Returns a {@link MetadataGeneratorConfigurer} for customization of the {@link MetadataGenerator}, {@link
     * MetadataGeneratorFilter} and
     * {@link MetadataDisplayFilter}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getMetadataGenerator()}.
     * <p>
     * Metadata Generator is for generation of service provider metadata describing the application in the current
     * deployment environment. All the URLs in the metadata will be derived from information in the
     * ServletContext.<br/>
     * Metadata Generator Filter and Metadata Display Filter expect calls on configured URL and presents user with
     * SAML2 metadata representing this application deployment. In case the application is configured to automatically
     * generate metadata, the generation occurs upon first invocation of this filter (first request made to the server).
     * </p>
     *
     * @return the {@link MetadataGeneratorConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public MetadataGeneratorConfigurer metadataGenerator() {
        return getOrApply(new MetadataGeneratorConfigurer());
    }

    /**
     * Provide a specific {@link MetadataGenerator}. Either use this method or {@link #sloProfile()}.
     * Alternatively define a {@link MetadataGenerator} bean.
     * <p>
     * Returns a {@link MetadataGeneratorConfigurer} for customization of the {@link MetadataGenerator}, {@link
     * MetadataGeneratorFilter} and
     * {@link MetadataDisplayFilter}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getMetadataGenerator()}.
     * <p>
     * Metadata Generator is for generation of service provider metadata describing the application in the current
     * deployment environment. All the URLs in the metadata will be derived from information in the
     * ServletContext.<br/>
     * Metadata Generator Filter and Metadata Display Filter expect calls on configured URL and presents user with
     * SAML2 metadata representing this application deployment. In case the application is configured to automatically
     * generate metadata, the generation occurs upon first invocation of this filter (first request made to the server).
     * </p>
     *
     * @return the {@link MetadataGeneratorConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public MetadataGeneratorConfigurer metadataGenerator(MetadataGenerator metadataGenerator) {
        return getOrApply(new MetadataGeneratorConfigurer(metadataGenerator));
    }

    /**
     * Returns a {@link MetadataGeneratorConfigurer} for customization of the {@link SAMLEntryPoint}, {@link
     * SAMLProcessingFilter},
     * {@link SAMLWebSSOHoKProcessingFilter} and {@link SAMLDiscovery}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties}.
     * <p>
     * SAML Entry Point initializes SAML WebSSO Profile, IDP Discovery or ECP Profile from the SP side. Configuration
     * of
     * the local service provider and incoming request determines which profile will get invoked.
     * There are two ways the entry point can get invoked. Either user accesses a URL configured to require some degree
     * of authentication and throws AuthenticationException which is handled and invokes the entry point. The other way
     * is direct invocation of the entry point by accessing the /saml/login URL.<br/>
     * SAML Processor Filter processes arriving SAML messages by delegating to the WebSSOProfile. After the
     * SAMLAuthenticationToken is obtained, authentication providers are asked to authenticate it.<br/>
     * SAML HOK Processing Filter processes messages sent from IDP as part of the WebSSO Holder-of-Key profile.<br/>
     * SAML Discovery implements Identity Provider Discovery Service and Profile as defined in
     * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf.
     * </p>
     *
     * @return the {@link SSOConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public SSOConfigurer sso() {
        return getOrApply(new SSOConfigurer());
    }

    /**
     * Returns a {@link TLSConfigurer} for customization of the {@link TLSProtocolConfigurer}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getTls()}.
     * <p>
     * TLS Protocol Configurer initializes instance of TLSProtocolSocketFactory and registers is at one of the protocol
     * inside HTTP Client. It also automatically makes the MetadataManager dependant on this bean.
     * </p>
     *
     * @return the {@link TLSConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public TLSConfigurer tls() {
        return getOrApply(new TLSConfigurer());
    }

    /**
     * Returns the original {@link HttpSecurity} to continue chaining configuration.
     */
    public HttpSecurity http() {
        return Optional.ofNullable(getSharedObject(HttpSecurity.class))
                .orElseThrow(() -> new IllegalStateException("HttpSecurity has not been set"));
    }

    /**
     * Allows for processing the original {@link HttpSecurity} AFTER the Service Provider configurer is configured. This is a workaround
     * to allow configuration to be chained after the configuration of the Service Provider has taken effect since Spring Security Configurers
     * are evaluated late in the game.
     */
    public ServiceProviderBuilder http(CheckedConsumer<HttpSecurity, Exception> httpConsumer) {
        setSharedObject(CheckedConsumer.class, httpConsumer);
        return this;
    }
}
