package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.*;

import java.util.*;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * @author Ulises Bocchio
 */
@Configuration
@EnableConfigurationProperties(SAMLSSOProperties.class)
public class SAMLServiceProviderSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private List<ServiceProviderConfigurer> serviceProviderConfigurers = Collections.emptyList();

    @Autowired
    private ObjectPostProcessor<Object> objectPostProcessor;

    @Autowired
    private SAMLSSOProperties sAMLSsoProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    DefaultListableBeanFactory beanFactory;

    @Autowired(required = false)
    private ExtendedMetadata extendedMetadata;

    @Autowired(required = false)
    SAMLContextProvider samlContextProvider;

    @Autowired(required = false)
    KeyManager keyManager;

    @Autowired(required = false)
    MetadataManager metadataManager;

    @Autowired(required = false)
    SAMLProcessor samlProcessor;

    @Autowired(required = false)
    @Qualifier("webSSOprofileConsumer")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfileConsumer webSSOProfileConsumer;

    @Autowired(required = false)
    @Qualifier("hokWebSSOprofileConsumer")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    WebSSOProfileConsumerHoKImpl hokWebSSOProfileConsumer;

    @Autowired(required = false)
    @Qualifier("webSSOprofile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    WebSSOProfile webSSOProfile;

    @Autowired(required = false)
    @Qualifier("ecpProfile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    WebSSOProfileECPImpl ecpProfile;

    @Autowired(required = false)
    @Qualifier("hokWebSSOProfile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    WebSSOProfileHoKImpl hokWebSSOProfile;

    @Autowired(required = false)
    SingleLogoutProfile sloProfile;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ServiceProviderSecurityBuilder securityConfigurerBuilder = new ServiceProviderSecurityBuilder(objectPostProcessor, beanFactory, beanRegistry());
        securityConfigurerBuilder.setSharedObject(ParserPool.class, ParserPoolHolder.getPool());
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerImpl.class, (WebSSOProfileConsumerImpl) webSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(ServiceProviderEndpoints.class, new ServiceProviderEndpoints());
        securityConfigurerBuilder.setSharedObject(ResourceLoader.class, resourceLoader);
        securityConfigurerBuilder.setSharedObject(SAMLSSOProperties.class, sAMLSsoProperties);
        securityConfigurerBuilder.setSharedObject(ExtendedMetadata.class, extendedMetadata);
        securityConfigurerBuilder.setSharedObject(AuthenticationManager.class, authenticationManagerBean());
        securityConfigurerBuilder.setSharedObject(BeanRegistry.class, beanRegistry());

        securityConfigurerBuilder.setSharedObject(SAMLContextProvider.class, samlContextProvider);
        securityConfigurerBuilder.setSharedObject(KeyManager.class, keyManager);
        securityConfigurerBuilder.setSharedObject(MetadataManager.class, metadataManager);
        securityConfigurerBuilder.setSharedObject(SAMLProcessor.class, samlProcessor);
        securityConfigurerBuilder.setSharedObject(WebSSOProfile.class, webSSOProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileECPImpl.class, ecpProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileHoKImpl.class, hokWebSSOProfile);
        securityConfigurerBuilder.setSharedObject(SingleLogoutProfile.class, sloProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumer.class, webSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);

        markBeansAsRegistered(securityConfigurerBuilder.getSharedObjects());

        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(http)));
        serviceProviderConfigurers.stream().forEach(unchecked(c -> c.configure(securityConfigurerBuilder)));
        ServiceProviderSecurityConfigurer securityConfigurer = securityConfigurerBuilder.build();
        securityConfigurer.init(http);
        securityConfigurer.configure(http);
    }

    private void markBeansAsRegistered(Map<Class<Object>, Object> sharedObjects) {
        sharedObjects.entrySet()
                .forEach(entry -> beanRegistry().addRegistered(entry.getKey(), entry.getValue()));
    }


    @Autowired(required = false)
    public void setServiceProviderConfigurers(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        this.serviceProviderConfigurers = serviceProviderConfigurers;
    }

    @Bean
    public BeanRegistry beanRegistry() {
        return new BeanRegistry(beanFactory);
    }

    @Slf4j
    public static class BeanRegistry implements DisposableBean {
        private Map<String, Object> singletons = new HashMap<>();
        private Map<Class<?>, Object> registeredBeans = new HashMap<>();
        private DefaultListableBeanFactory beanFactory;

        public BeanRegistry(DefaultListableBeanFactory beanFactory) {
            this.beanFactory = beanFactory;
        }

        public void addSingleton(String name, Object bean) {
            Optional.ofNullable(bean)
                    .ifPresent(b -> singletons.put(name, bean));
        }

        public void addRegistered(Object bean) {
            addRegistered(bean.getClass(), bean);
        }

        public void addRegistered(Class<?> clazz, Object bean) {
            Optional.ofNullable(bean)
                    .ifPresent(b -> registeredBeans.put(clazz, bean));
        }

        public boolean isRegistered(Object bean) {
            return Optional.ofNullable(bean)
                    .map(Object::getClass)
                    .map(registeredBeans::containsKey)
                    .orElse(false);
        }

        public void destroy() throws Exception {
            singletons.keySet()
                    .stream()
                    .forEach(this::destroySingleton);
        }

        private void destroySingleton(String beanName) {
            log.debug("Destroying singleton: {}", beanName);
            beanFactory.destroySingleton(beanName);
        }
    }
}
