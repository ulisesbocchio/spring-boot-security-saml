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
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.websso.*;

import java.util.stream.Stream;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
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
        Stream.<Class<? extends SecurityConfigurerAdapter<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>>>of(
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

    public SAMLContextProviderConfigurer samlContextProvider() throws Exception {
        return getOrApply(new SAMLContextProviderConfigurer());
    }

    public SAMLContextProviderConfigurer samlContextProvider(SAMLContextProvider samlContextProvider) throws Exception {
        return getOrApply(new SAMLContextProviderConfigurer(samlContextProvider));
    }

    public MetadataManagerConfigurer metadataManager() throws Exception {
        return getOrApply(new MetadataManagerConfigurer());
    }

    public MetadataManagerConfigurer metadataManager(MetadataManager metadataManager) throws Exception {
        return getOrApply(new MetadataManagerConfigurer(metadataManager));
    }

    public KeyManagerConfigurer keyManager() throws Exception {
        return getOrApply(new KeyManagerConfigurer());
    }

    public KeyManagerConfigurer keyManager(KeyManager keyManager) throws Exception {
        return getOrApply(new KeyManagerConfigurer(keyManager));
    }

    public SAMLProcessorConfigurer samlProcessor() throws Exception {
        return getOrApply(new SAMLProcessorConfigurer());
    }

    public SAMLProcessorConfigurer samlProcessor(SAMLProcessor samlProcessor) throws Exception {
        return getOrApply(new SAMLProcessorConfigurer(samlProcessor));
    }

    public WebSSOProfileConsumerConfigurer ssoProfileConsumer() throws Exception {
        return getOrApply(new WebSSOProfileConsumerConfigurer());
    }

    public WebSSOProfileConsumerConfigurer ssoProfileConsumer(WebSSOProfileConsumer ssoProfileConsumer) throws Exception {
        return getOrApply(new WebSSOProfileConsumerConfigurer(ssoProfileConsumer));
    }

    public WebSSOProfileHoKConsumerConfigurer hokProfileConsumer() throws Exception {
        return getOrApply(new WebSSOProfileHoKConsumerConfigurer());
    }

    public WebSSOProfileHoKConsumerConfigurer hokProfileConsumer(WebSSOProfileConsumerHoKImpl hokProfileConsumer) throws Exception {
        return getOrApply(new WebSSOProfileHoKConsumerConfigurer(hokProfileConsumer));
    }

    public WebSSOProfileConfigurer ssoProfile() throws Exception {
        return getOrApply(new WebSSOProfileConfigurer());
    }

    public WebSSOProfileConfigurer ssoProfile(WebSSOProfile ssoProfile) throws Exception {
        return getOrApply(new WebSSOProfileConfigurer(ssoProfile));
    }

    public WebSSOProfileECPConfigurer ecpProfile() throws Exception {
        return getOrApply(new WebSSOProfileECPConfigurer());
    }

    public WebSSOProfileECPConfigurer ecpProfile(WebSSOProfileECPImpl ecpProfile) throws Exception {
        return getOrApply(new WebSSOProfileECPConfigurer(ecpProfile));
    }

    public WebSSOProfileHoKConfigurer hokProfile() throws Exception {
        return getOrApply(new WebSSOProfileHoKConfigurer());
    }

    public WebSSOProfileHoKConfigurer hokProfile(WebSSOProfileHoKImpl hokProfile) throws Exception {
        return getOrApply(new WebSSOProfileHoKConfigurer(hokProfile));
    }

    public SingleLogoutProfileConfigurer sloProfile() throws Exception {
        return getOrApply(new SingleLogoutProfileConfigurer());
    }

    public SingleLogoutProfileConfigurer sloProfile(SingleLogoutProfile sloProfile) throws Exception {
        return getOrApply(new SingleLogoutProfileConfigurer(sloProfile));
    }

    public ExtendedMetadataConfigurer extendedMetadata() throws Exception {
        return getOrApply(new ExtendedMetadataConfigurer());
    }

    public ExtendedMetadataConfigurer extendedMetadata(ExtendedMetadata extendedMetadata) throws Exception {
        return getOrApply(new ExtendedMetadataConfigurer(extendedMetadata));
    }

    public AuthenticationProviderConfigurer authenticationProvider() throws Exception {
        return authenticationProvider(new SAMLAuthenticationProvider());
    }

    public AuthenticationProviderConfigurer authenticationProvider(SAMLAuthenticationProvider provider) throws Exception {
        return getOrApply(new AuthenticationProviderConfigurer(provider));
    }

    public LogoutConfigurer logout() throws Exception {
        return getOrApply(new LogoutConfigurer());
    }

    public MetadataGeneratorConfigurer metadataGenerator() throws Exception {
        return getOrApply(new MetadataGeneratorConfigurer());
    }

    public SSOConfigurer sso() throws Exception {
        return getOrApply(new SSOConfigurer());
    }

    public TLSConfigurer tls() throws Exception {
        return getOrApply(new TLSConfigurer());
    }
}
