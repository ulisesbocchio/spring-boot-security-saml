package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.configuration.SAMLServiceProviderSecurityConfiguration.BeanRegistry;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder.*;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.AutowiringObjectPostProcessor;
import com.github.ulisesbocchio.spring.boot.security.saml.util.CompositeObjectPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.websso.*;

import java.util.stream.Stream;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * Class for internal usage of this Spring Boot Plugin. It deals with all the nitty-gritty of wiring all required
 * Spring Security SAML beans, while also exposing most aspects of its configuration through 2 different methods:
 * <ul>
 * <li>Custom Beans</li>
 * <li>A java DSL using Spring Security's builder classes</li>
 * <li>Exposed configuration properties through {@link SAMLSSOProperties}</li>
 * </ul>
 * all three methods can be used exclusively or mixed. Explicit Bean Definition always takes precedence. Explicit configuration
 * through the DSL always takes precedence over the properties. Most options provide configuration overrides by specifying
 * a Bean of certain type, but not everything. Check with the Javadoc of each method for further details.
 *
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer> {

    private CompositeObjectPostProcessor compositePostProcessor = new CompositeObjectPostProcessor();
    private DefaultListableBeanFactory beanFactory;
    private BeanRegistry beanRegistry;

    public ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor, DefaultListableBeanFactory beanFactory, BeanRegistry beanRegistry) {
        super(objectPostProcessor, false);
        this.beanFactory = beanFactory;
        this.beanRegistry = beanRegistry;
        //custom post processor that provides Autowiring capabilities.
        compositePostProcessor.addObjectPostProcessor(new AutowiringObjectPostProcessor(beanFactory));
        compositePostProcessor.addObjectPostProcessor(objectPostProcessor);
        objectPostProcessor(compositePostProcessor);
    }

    private void registerBean(String name, Object o) {
        if (!beanRegistry.isRegistered(o)) {
            beanRegistry.addSingleton(name, o);
            beanFactory.registerSingleton(name, o);
        }
    }

    private void registerBean(Object o) {
        registerBean(o.getClass().getName(), o);
    }

    @Override
    public <C> void setSharedObject(Class<C> sharedType, C object) {
        if (object != null) {
            super.setSharedObject(sharedType, object);
        }
    }

    private <C extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>> C getOrApply(
            C configurer) throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }

    private <C extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>> C removeConfigurerAdapter(Class<C> configurer) {
        return removeConfigurer(configurer);
    }

    @Override
    protected void beforeInit() throws Exception {
        //All configurers are initialized only once.
        keyManager();
        extendedMetadata();
        metadataManager();
        samlContextProvider();
        samlProcessor();
        authenticationProvider();
        ssoProfileConsumer();
        hokProfileConsumer();
        ssoProfile();
        ecpProfile();
        hokProfile();
        sloProfile();
        logout();
        sso();
        tls();
        metadataGenerator();
        //make sure they're in the right order.
        reorderConfigurers();
    }

    private void reorderConfigurers() {
        //Order of configurers is established by the following stream.
        Stream.of(
                KeyManagerConfigurer.class,
                ExtendedMetadataConfigurer.class,
                MetadataManagerConfigurer.class,
                AuthenticationProviderConfigurer.class,
                SAMLContextProviderConfigurer.class,
                SAMLProcessorConfigurer.class,
                WebSSOProfileConsumerConfigurer.class,
                WebSSOProfileHoKConsumerConfigurer.class,
                WebSSOProfileConfigurer.class,
                WebSSOProfileECPConfigurer.class,
                WebSSOProfileHoKConfigurer.class,
                SingleLogoutProfileConfigurer.class,
                LogoutConfigurer.class,
                SSOConfigurer.class,
                TLSConfigurer.class,
                MetadataGeneratorConfigurer.class)
                .map(this::removeConfigurerAdapter)
                .forEach(unchecked(this::getOrApply));
    }

    @Override
    protected ServiceProviderSecurityConfigurer performBuild() throws Exception {
        //Some shared objects need to be registered as Spring Beans for proper Autowiring and initialization.
        //Some shared objects need to be registered as Spring Bean with specific names, as they are autowired by other
        //beans with name qualifiers.
        KeyManager keyManager = getSharedObject(KeyManager.class);
        registerBean(keyManager);
        MetadataManager metadataManager = getSharedObject(MetadataManager.class);
        registerBean(metadataManager);
        SAMLContextProvider samlContextProvider = getSharedObject(SAMLContextProvider.class);
        registerBean(samlContextProvider);
        SAMLProcessor samlProcessor = getSharedObject(SAMLProcessor.class);
        registerBean(samlProcessor);
        WebSSOProfileConsumer webSSOprofileConsumer = getSharedObject(WebSSOProfileConsumer.class);
        registerBean("webSSOprofileConsumer", webSSOprofileConsumer);
        WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer = getSharedObject(WebSSOProfileConsumerHoKImpl.class);
        registerBean("hokWebSSOprofileConsumer", hokWebSSOprofileConsumer);
        WebSSOProfile webSSOProfile = getSharedObject(WebSSOProfile.class);
        registerBean("webSSOprofile", webSSOProfile);
        WebSSOProfileECPImpl ecpProfile = getSharedObject(WebSSOProfileECPImpl.class);
        registerBean("ecpProfile", ecpProfile);
        WebSSOProfileHoKImpl hokWebSSOProfile = getSharedObject(WebSSOProfileHoKImpl.class);
        registerBean("hokWebSSOProfile", hokWebSSOProfile);
        SingleLogoutProfile sloProfile = getSharedObject(SingleLogoutProfile.class);
        registerBean(sloProfile);
        MetadataGenerator metadataGenerator = getSharedObject(MetadataGenerator.class);
        registerBean(metadataGenerator);

        SAMLSSOProperties config = getSharedObject(SAMLSSOProperties.class);

        SAMLAuthenticationProvider authenticationProvider = getSharedObject(SAMLAuthenticationProvider.class);
        registerBean(authenticationProvider);

        SAMLLogoutFilter samlLogoutFilter = getSharedObject(SAMLLogoutFilter.class);
        registerBean(samlLogoutFilter);
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = getSharedObject(SAMLLogoutProcessingFilter.class);
        registerBean(samlLogoutProcessingFilter);

        MetadataDisplayFilter metadataDisplayFilter = getSharedObject(MetadataDisplayFilter.class);
        registerBean(metadataDisplayFilter);
        MetadataGeneratorFilter metadataGeneratorFilter = getSharedObject(MetadataGeneratorFilter.class);
        registerBean(metadataGeneratorFilter);

        SAMLProcessingFilter sAMLProcessingFilter = getSharedObject(SAMLProcessingFilter.class);
        registerBean(sAMLProcessingFilter);
        SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter = getSharedObject(SAMLWebSSOHoKProcessingFilter.class);
        registerBean(sAMLWebSSOHoKProcessingFilter);
        SAMLDiscovery sAMLDiscovery = getSharedObject(SAMLDiscovery.class);
        registerBean(sAMLDiscovery);
        SAMLEntryPoint sAMLEntryPoint = getSharedObject(SAMLEntryPoint.class);
        registerBean(sAMLEntryPoint);

        TLSProtocolConfigurer tlsProtocolConfigurer = getSharedObject(TLSProtocolConfigurer.class);
        tlsProtocolConfigurer.setKeyManager(keyManager);
        registerBean(tlsProtocolConfigurer);

        ServiceProviderEndpoints endpoints = getSharedObject(ServiceProviderEndpoints.class);

        postProcess(webSSOprofileConsumer);
        postProcess(samlContextProvider);
        postProcess(webSSOProfile);
        postProcess(ecpProfile);
        postProcess(hokWebSSOProfile);
        postProcess(sloProfile);
        postProcess(webSSOprofileConsumer);
        postProcess(hokWebSSOprofileConsumer);
        metadataGenerator.setSamlEntryPoint(sAMLEntryPoint);
        metadataGenerator.setSamlLogoutProcessingFilter(samlLogoutProcessingFilter);
        metadataGenerator.setSamlWebSSOFilter(sAMLProcessingFilter);
        metadataGenerator.setSamlWebSSOHoKFilter(sAMLWebSSOHoKProcessingFilter);
        postProcess(metadataGenerator);

        ServiceProviderSecurityConfigurer httpSecurityConfigurer = new ServiceProviderSecurityConfigurer(config, metadataManager, authenticationProvider, samlProcessor,
                samlLogoutFilter, samlLogoutProcessingFilter, metadataDisplayFilter, metadataGeneratorFilter,
                sAMLProcessingFilter, sAMLWebSSOHoKProcessingFilter, sAMLDiscovery, sAMLEntryPoint, keyManager,
                tlsProtocolConfigurer, endpoints);
        httpSecurityConfigurer.addObjectPostProcessor(compositePostProcessor);
        return httpSecurityConfigurer;
    }

    /**
     * Returns a {@link SAMLContextProviderConfigurer} for customization of the {@link SAMLContextProvider} default
     * implementation {@link SAMLContextProviderImpl}. Either use this method or {@link #samlContextProvider(SAMLContextProvider)}.
     * Alternatively define a {@link SAMLContextProvider} bean.
     *
     * @return the {@link SAMLContextProvider} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SAMLContextProviderConfigurer samlContextProvider() throws Exception {
        return getOrApply(new SAMLContextProviderConfigurer());
    }

    /**
     * Provide a specific {@link SAMLContextProvider}. Either use this method or {@link #samlContextProvider()}.
     * Alternatively define a {@link SAMLContextProvider} bean.
     *
     * @param samlContextProvider the context provider to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder samlContextProvider(SAMLContextProvider samlContextProvider) throws Exception {
        getOrApply(new SAMLContextProviderConfigurer(samlContextProvider));
        return this;
    }

    /**
     * Returns a {@link MetadataManagerConfigurer} for customization of the {@link MetadataManager} default
     * implementation {@link CachingMetadataManager}. Either use this method or {@link #metadataManager(MetadataManager)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getMetadataManager()} and {@link SAMLSSOProperties#getExtendedDelegate()}.
     * Alternatively define a {@link MetadataManager} bean.
     *
     * @return the {@link MetadataManager} configurer.
     * @throws Exception Any exception during configuration.
     */
    public MetadataManagerConfigurer metadataManager() throws Exception {
        return getOrApply(new MetadataManagerConfigurer());
    }

    /**
     * Provide a specific {@link MetadataManager}. Either use this method or {@link #metadataManager()}.
     * Alternatively define a {@link MetadataManager} bean.
     *
     * @param metadataManager the metadata Manager to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder metadataManager(MetadataManager metadataManager) throws Exception {
        getOrApply(new MetadataManagerConfigurer(metadataManager));
        return this;
    }

    /**
     * Returns a {@link KeyManagerConfigurer} for customization of the {@link KeyManager} default
     * implementation {@link JKSKeyManager}. Either use this method or {@link #keyManager(KeyManager)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getKeyManager()}.
     * Alternatively define a {@link KeyManager} bean.
     *
     * @return the {@link KeyManager} configurer.
     * @throws Exception Any exception during configuration.
     */
    public KeyManagerConfigurer keyManager() throws Exception {
        return getOrApply(new KeyManagerConfigurer());
    }

    /**
     * Provide a specific {@link KeyManager}. Either use this method or {@link #keyManager()}.
     * Alternatively define a {@link KeyManager} bean.
     *
     * @param keyManager the key Manager to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder keyManager(KeyManager keyManager) throws Exception {
        getOrApply(new KeyManagerConfigurer(keyManager));
        return this;
    }

    /**
     * Returns a {@link SAMLProcessorConfigurer} for customization of the {@link SAMLProcessor} default
     * implementation {@link SAMLProcessorImpl}. Either use this method or {@link #samlProcessor(SAMLProcessor)}.
     * Alternatively use properties exposed at: {@link SAMLSSOProperties#getSamlProcessor()}.
     * Alternatively define a {@link SAMLProcessor} bean.
     *
     * @return the {@link SAMLProcessor} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SAMLProcessorConfigurer samlProcessor() throws Exception {
        return getOrApply(new SAMLProcessorConfigurer());
    }

    /**
     * Provide a specific {@link SAMLProcessor}. Either use this method or {@link #samlProcessor()}.
     * Alternatively define a {@link SAMLProcessor} bean.
     *
     * @param samlProcessor the saml Processor to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder samlProcessor(SAMLProcessor samlProcessor) throws Exception {
        getOrApply(new SAMLProcessorConfigurer(samlProcessor));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileConsumerConfigurer} for customization of the {@link WebSSOProfileConsumer} default
     * implementation {@link WebSSOProfileConsumerImpl}. Either use this method or {@link #ssoProfileConsumer(WebSSOProfileConsumer)}.
     * Alternatively define a {@link WebSSOProfileConsumer} bean with name webSSOprofileConsumer.
     *
     * @return the {@link WebSSOProfileConsumer} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileConsumerConfigurer ssoProfileConsumer() throws Exception {
        return getOrApply(new WebSSOProfileConsumerConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileConsumer}. Either use this method or {@link #ssoProfileConsumer()}.
     * Alternatively define a {@link WebSSOProfileConsumer} bean with name webSSOprofileConsumer.
     *
     * @param ssoProfileConsumer the sso Profile Consumer to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder ssoProfileConsumer(WebSSOProfileConsumer ssoProfileConsumer) throws Exception {
        getOrApply(new WebSSOProfileConsumerConfigurer(ssoProfileConsumer));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileHoKConsumerConfigurer} for customization of the {@link WebSSOProfileConsumerHoKImpl} default
     * implementation {@link WebSSOProfileConsumerHoKImpl}. Either use this method or {@link #hokProfileConsumer(WebSSOProfileConsumerHoKImpl)}.
     * Alternatively define a {@link WebSSOProfileConsumerHoKImpl} bean with name hokWebSSOprofileConsumer.
     *
     * @return the {@link WebSSOProfileConsumerHoKImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileHoKConsumerConfigurer hokProfileConsumer() throws Exception {
        return getOrApply(new WebSSOProfileHoKConsumerConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileConsumerHoKImpl}. Either use this method or {@link #hokProfileConsumer()}.
     * Alternatively define a {@link WebSSOProfileConsumerHoKImpl} bean with name hokWebSSOprofileConsumer.
     *
     * @param hokProfileConsumer the hok Profile Consumer to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder hokProfileConsumer(WebSSOProfileConsumerHoKImpl hokProfileConsumer) throws Exception {
        getOrApply(new WebSSOProfileHoKConsumerConfigurer(hokProfileConsumer));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileConfigurer} for customization of the {@link WebSSOProfile} default
     * implementation {@link WebSSOProfileImpl}. Either use this method or {@link #ssoProfile(WebSSOProfile)}.
     * Alternatively define a {@link WebSSOProfile} bean with name webSSOprofile.
     *
     * @return the {@link WebSSOProfile} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileConfigurer ssoProfile() throws Exception {
        return getOrApply(new WebSSOProfileConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfile}. Either use this method or {@link #ssoProfile()}.
     * Alternatively define a {@link WebSSOProfile} bean with name webSSOprofile.
     *
     * @param ssoProfile the sso Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder ssoProfile(WebSSOProfile ssoProfile) throws Exception {
        getOrApply(new WebSSOProfileConfigurer(ssoProfile));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileECPConfigurer} for customization of the {@link WebSSOProfileECPImpl} default
     * implementation {@link WebSSOProfileECPImpl}. Either use this method or {@link #ecpProfile(WebSSOProfileECPImpl)}.
     * Alternatively define a {@link WebSSOProfileECPImpl} bean with name ecpProfile.
     *
     * @return the {@link WebSSOProfileECPImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileECPConfigurer ecpProfile() throws Exception {
        return getOrApply(new WebSSOProfileECPConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileECPImpl}. Either use this method or {@link #ecpProfile()}.
     * Alternatively define a {@link WebSSOProfileECPImpl} bean with name ecpProfile.
     *
     * @param ecpProfile the ecp Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder ecpProfile(WebSSOProfileECPImpl ecpProfile) throws Exception {
        getOrApply(new WebSSOProfileECPConfigurer(ecpProfile));
        return this;
    }

    /**
     * Returns a {@link WebSSOProfileHoKConfigurer} for customization of the {@link WebSSOProfileHoKImpl} default
     * implementation {@link WebSSOProfileHoKImpl}. Either use this method or {@link #hokProfile(WebSSOProfileHoKImpl)}.
     * Alternatively define a {@link WebSSOProfileHoKImpl} bean with name hokWebSSOProfile.
     *
     * @return the {@link WebSSOProfileHoKImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public WebSSOProfileHoKConfigurer hokProfile() throws Exception {
        return getOrApply(new WebSSOProfileHoKConfigurer());
    }

    /**
     * Provide a specific {@link WebSSOProfileHoKImpl}. Either use this method or {@link #hokProfile()}.
     * Alternatively define a {@link WebSSOProfileHoKImpl} bean with name hokWebSSOProfile.
     *
     * @param hokProfile the hok Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder hokProfile(WebSSOProfileHoKImpl hokProfile) throws Exception {
        getOrApply(new WebSSOProfileHoKConfigurer(hokProfile));
        return this;
    }

    /**
     * Returns a {@link SingleLogoutProfileConfigurer} for customization of the {@link SingleLogoutProfile} default
     * implementation {@link SingleLogoutProfileImpl}. Either use this method or {@link #sloProfile(SingleLogoutProfile)}.
     * Alternatively define a {@link SingleLogoutProfile} bean.
     *
     * @return the {@link SingleLogoutProfileImpl} configurer.
     * @throws Exception Any exception during configuration.
     */
    public SingleLogoutProfileConfigurer sloProfile() throws Exception {
        return getOrApply(new SingleLogoutProfileConfigurer());
    }

    /**
     * Provide a specific {@link SingleLogoutProfile}. Either use this method or {@link #sloProfile()}.
     * Alternatively define a {@link SingleLogoutProfile} bean.
     *
     * @param sloProfile the slo Profile to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder sloProfile(SingleLogoutProfile sloProfile) throws Exception {
        getOrApply(new SingleLogoutProfileConfigurer(sloProfile));
        return this;
    }

    /**
     * Returns a {@link ExtendedMetadataConfigurer} for customization of the {@link ExtendedMetadata} default
     * implementation {@link ExtendedMetadata}. Either use this method or {@link #extendedMetadata(ExtendedMetadata)}.
     * Alternatively define a {@link ExtendedMetadata} bean.
     *
     * @return the {@link ExtendedMetadata} configurer.
     * @throws Exception Any exception during configuration.
     */
    public ExtendedMetadataConfigurer extendedMetadata() throws Exception {
        return getOrApply(new ExtendedMetadataConfigurer());
    }

    /**
     * Provide a specific {@link ExtendedMetadata}. Either use this method or {@link #extendedMetadata()}.
     * Alternatively define a {@link ExtendedMetadata} bean.
     *
     * @param extendedMetadata the extended Metadata to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder extendedMetadata(ExtendedMetadata extendedMetadata) throws Exception {
        getOrApply(new ExtendedMetadataConfigurer(extendedMetadata));
        return this;
    }

    /**
     * Returns a {@link AuthenticationProviderConfigurer} for customization of the {@link SAMLAuthenticationProvider} default
     * implementation {@link SAMLAuthenticationProvider}. Either use this method or {@link #authenticationProvider(SAMLAuthenticationProvider)}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getAuthenticationProvider()}
     * Alternatively define a {@link SAMLAuthenticationProvider} bean.
     *
     * @return the {@link SAMLAuthenticationProvider} configurer.
     * @throws Exception Any exception during configuration.
     */
    public AuthenticationProviderConfigurer authenticationProvider() throws Exception {
        return getOrApply(new AuthenticationProviderConfigurer());
    }

    /**
     * Provide a specific {@link SAMLAuthenticationProvider}. Either use this method or {@link #authenticationProvider()}.
     * Alternatively define a {@link SAMLAuthenticationProvider} bean.
     *
     * @param provider the authentication Provider to use.
     * @return this builder for further customization.
     * @throws Exception Any exception during configuration.
     */
    public ServiceProviderSecurityBuilder authenticationProvider(SAMLAuthenticationProvider provider) throws Exception {
        getOrApply(new AuthenticationProviderConfigurer(provider));
        return this;
    }

    /**
     * Returns a {@link AuthenticationProviderConfigurer} for customization of the {@link SAMLLogoutFilter} and
     * {@link SAMLProcessingFilter}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getLogout()}
     *
     * @return the {@link LogoutConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public LogoutConfigurer logout() throws Exception {
        return getOrApply(new LogoutConfigurer());
    }

    /**
     * Returns a {@link MetadataGeneratorConfigurer} for customization of the {@link MetadataGenerator}, {@link MetadataGeneratorFilter} and
     * {@link MetadataDisplayFilter}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getMetadataGenerator()}
     *
     * @return the {@link MetadataGeneratorConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public MetadataGeneratorConfigurer metadataGenerator() throws Exception {
        return getOrApply(new MetadataGeneratorConfigurer());
    }

    /**
     * Returns a {@link MetadataGeneratorConfigurer} for customization of the {@link SAMLEntryPoint}, {@link SAMLProcessingFilter},
     * {@link SAMLWebSSOHoKProcessingFilter} and {@link SAMLDiscovery}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties}
     *
     * @return the {@link MetadataGeneratorConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public SSOConfigurer sso() throws Exception {
        return getOrApply(new SSOConfigurer());
    }

    /**
     * Returns a {@link TLSConfigurer} for customization of the {@link TLSProtocolConfigurer}.
     * Alternatively use properties exposed at {@link SAMLSSOProperties#getTls()}
     *
     * @return the {@link TLSConfigurer}
     * @throws Exception Any exception during configuration.
     */
    public TLSConfigurer tls() throws Exception {
        return getOrApply(new TLSConfigurer());
    }
}
