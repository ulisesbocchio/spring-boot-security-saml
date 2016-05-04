package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder.*;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSsoProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.AutowiringObjectPostProcessor;
import com.github.ulisesbocchio.spring.boot.security.saml.util.CompositeObjectPostProcessor;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.SingletonBeanRegistry;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.websso.*;

/**
 * @author Ulises Bocchio
 */
public class ServiceProviderSecurityBuilder extends
        AbstractConfiguredSecurityBuilder<ServiceProviderSecurityConfigurer, ServiceProviderSecurityBuilder>
        implements SecurityBuilder<ServiceProviderSecurityConfigurer> {

    private CompositeObjectPostProcessor compositePostProcessor = new CompositeObjectPostProcessor();
    private AutowireCapableBeanFactory beanFactory;
    private SingletonBeanRegistry singletonBeanRegistry;

    public ServiceProviderSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor, AutowireCapableBeanFactory beanFactory, SingletonBeanRegistry singletonBeanRegistry) {
        super(objectPostProcessor, false);
        this.beanFactory = beanFactory;
        this.singletonBeanRegistry = singletonBeanRegistry;
        compositePostProcessor.addObjectPostProcessor(new AutowiringObjectPostProcessor(beanFactory));
        compositePostProcessor.addObjectPostProcessor(objectPostProcessor);
        objectPostProcessor(compositePostProcessor);
    }

    private void registerBean(String name, Object o) {
        if(!beanExists(o.getClass())) {
            singletonBeanRegistry.registerSingleton(name, o);
        }
    }

    private void registerBean(Object o) {
        registerBean(o.getClass().getName(), o);
    }

    private boolean beanExists(Class<?> beanType) {
        try {
            beanFactory.getBean(beanType);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public <C> void setSharedObject(Class<C> sharedType, C object) {
        if(object != null) {
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

    @Override
    protected void beforeInit() throws Exception {
        keyManager();
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
        WebSSOProfile webSSOProfile = getSharedObject(WebSSOProfile.class);
        registerBean("webSSOprofile", webSSOProfile);
        WebSSOProfileECPImpl ecpProfile = getSharedObject(WebSSOProfileECPImpl.class);
        registerBean("hokProfile", ecpProfile);
        WebSSOProfileHoKImpl hokWebSSOProfile = getSharedObject(WebSSOProfileHoKImpl.class);
        registerBean("hokWebSSOProfile", hokWebSSOProfile);
        SingleLogoutProfile sloProfile = getSharedObject(SingleLogoutProfile.class);
        registerBean(sloProfile);
        WebSSOProfileConsumer webSSOprofileConsumer = getSharedObject(WebSSOProfileConsumer.class);
        registerBean("webSSOprofileConsumer", webSSOprofileConsumer);
        WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer = getSharedObject(WebSSOProfileConsumerHoKImpl.class);
        registerBean("hokWebSSOprofileConsumer", hokWebSSOprofileConsumer);

        SAMLSsoProperties config = getSharedObject(SAMLSsoProperties.class);

        SAMLAuthenticationProvider authenticationProvider = getSharedObject(SAMLAuthenticationProvider.class);

        SAMLLogoutFilter samlLogoutFilter = getSharedObject(SAMLLogoutFilter.class);
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = getSharedObject(SAMLLogoutProcessingFilter.class);

        MetadataDisplayFilter metadataDisplayFilter = getSharedObject(MetadataDisplayFilter.class);
        MetadataGeneratorFilter metadataGeneratorFilter = getSharedObject(MetadataGeneratorFilter.class);
        MetadataGenerator metadataGenerator = getSharedObject(MetadataGenerator.class);

        SAMLProcessingFilter sAMLProcessingFilter = getSharedObject(SAMLProcessingFilter.class);
        SAMLWebSSOHoKProcessingFilter sAMLWebSSOHoKProcessingFilter = getSharedObject(SAMLWebSSOHoKProcessingFilter.class);
        SAMLDiscovery sAMLDiscovery = getSharedObject(SAMLDiscovery.class);
        SAMLEntryPoint sAMLEntryPoint = getSharedObject(SAMLEntryPoint.class);

        metadataManager.setKeyManager(keyManager);
        metadataGenerator.setKeyManager(keyManager);

        TLSProtocolConfigurer tlsProtocolConfigurer = getSharedObject(TLSProtocolConfigurer.class);
        tlsProtocolConfigurer.setKeyManager(keyManager);

        ServiceProviderEndpoints endpoints = getSharedObject(ServiceProviderEndpoints.class);

        if (samlContextProvider instanceof SAMLContextProviderImpl) {
            ((SAMLContextProviderImpl) samlContextProvider).setKeyManager(keyManager);
            ((SAMLContextProviderImpl) samlContextProvider).setMetadata(metadataManager);
        }
        postProcess(samlContextProvider);

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
