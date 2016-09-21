package com.github.ulisesbocchio.spring.boot.security.saml.configuration;

import com.github.ulisesbocchio.spring.boot.security.saml.bean.SAMLConfigurerBean;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.util.BeanRegistry;
import lombok.Data;
import org.assertj.core.util.Lists;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * Spring Security configuration entry point for the Service Provider. This configuration class basically collects
 * all relevant beans present in the application context to initialize and configure all {@link
 * ServiceProviderConfigurer}
 * present in the context. Usually one {@link ServiceProviderConfigurer} is enough and preferably one that extends
 * {@link ServiceProviderConfigurerAdapter} which provides empty implementations and subclasses can implement only the
 * relevant method(s) for the purpose of the current application.
 * <p>
 * All {@code required=false} autowired beans can be provided as beans by the user instead of using the
 * {@link ServiceProviderConfigurer} DSL.
 *
 * @author Ulises Bocchio
 */
@Configuration
@EnableConfigurationProperties(SAMLSSOProperties.class)
public class SAMLServiceProviderSecurityConfiguration implements InitializingBean {

    @Autowired
    private ObjectPostProcessor<Object> objectPostProcessor;

    @Autowired
    private SAMLSSOProperties sAMLSsoProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    @Autowired
    private DefaultListableBeanFactory beanFactory;

    @Autowired(required = false)
    private ExtendedMetadata extendedMetadata;

    @Autowired(required = false)
    private SAMLContextProvider samlContextProvider;

    @Autowired(required = false)
    private KeyManager keyManager;

    @Autowired(required = false)
    private MetadataManager metadataManager;

    @Autowired(required = false)
    private MetadataGenerator metadataGenerator;

    @Autowired(required = false)
    private SAMLProcessor samlProcessor;

    @Autowired(required = false)
    @Qualifier("webSSOprofileConsumer")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfileConsumer webSSOProfileConsumer;

    @Autowired(required = false)
    @Qualifier("hokWebSSOprofileConsumer")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfileConsumerHoKImpl hokWebSSOProfileConsumer;

    @Autowired(required = false)
    @Qualifier("webSSOprofile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfile webSSOProfile;

    @Autowired(required = false)
    @Qualifier("ecpprofile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfileECPImpl ecpProfile;

    @Autowired(required = false)
    @Qualifier("hokWebSSOProfile")
    @SuppressWarnings("SpringJavaAutowiringInspection")
    private WebSSOProfileHoKImpl hokWebSSOProfile;

    @Autowired(required = false)
    private SingleLogoutProfile sloProfile;

    @Autowired(required = false)
    private SAMLAuthenticationProvider samlAuthenticationProvider;

    @Autowired(required = false)
    List<ServiceProviderConfigurer> serviceProviderConfigurers = Lists.newArrayList();

    @Autowired(required = false)
    SAMLConfigurerBean samlConfigurerBean;

    @Bean
    ServiceProviderBuilderHolder serviceProviderBuilderHolder() {
        return new ServiceProviderBuilderHolder();
    }

    @Data
    public static class ServiceProviderBuilderHolder {
        private ServiceProviderBuilder builder = null;
    }

    @Bean
    public WebSecurityConfigurer samlWebSecurityConfigurer() {
        return samlConfigurerBean == null ? new SAMLWebSecurityConfigurer(serviceProviderConfigurers, serviceProviderBuilderHolder()) : new NoWebSecurityConfigurerAdapter();
    }

    /**
     * Used as a fallback when the {@link SAMLConfigurerBean} method is used. Basically a dummy web security
     * configuration.
     */
    private static class NoWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements Ordered {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatcher(request -> false);
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }

    /**
     * Default Web Security Configurer that delegates configuration of the service provider to {@link
     * ServiceProviderConfigurer}
     */
    private static class SAMLWebSecurityConfigurer extends WebSecurityConfigurerAdapter implements Ordered {

        private List<ServiceProviderConfigurer> serviceProviderConfigurers = Collections.emptyList();
        private ServiceProviderBuilderHolder builderHolder;

        @SuppressWarnings("SpringJavaAutowiringInspection")
        public SAMLWebSecurityConfigurer(List<ServiceProviderConfigurer> serviceProviderConfigurers, ServiceProviderBuilderHolder builderHolder) {
            super(false);
            this.serviceProviderConfigurers = serviceProviderConfigurers;
            this.builderHolder = builderHolder;
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            serviceProviderConfigurers.forEach(unchecked(c -> c.configure(web)));
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            builderHolder.getBuilder().setSharedObject(AuthenticationManager.class, authenticationManagerBean());
            SAMLConfigurerBean saml = new SAMLConfigurerBean(builderHolder, authenticationManagerBean());

            http.apply(saml);

            // @formatter:off
            http.httpBasic()
                .disable()
                .csrf()
                .disable()
                .anonymous()
            .and()
                .apply(saml)
                .serviceProvider(serviceProviderConfigurers)
            .http()
                .authorizeRequests()
                .requestMatchers(saml.endpointsMatcher()).permitAll();

            serviceProviderConfigurers.forEach(unchecked(spc -> spc.configure(http)));

            http
                .authorizeRequests()
                .anyRequest()
                .authenticated();
            // @formatter:on
        }

        @Override
        public int getOrder() {
            return -17;
        }
    }

    public SAMLServiceProviderSecurityConfiguration() {
    }

    @Override
    public void afterPropertiesSet() {
        //All existing beans are thrown as shared objects to the ServiceProviderSecurityBuilder, which will wire all
        //beans/objects related to spring security SAML.
        ServiceProviderBuilder securityConfigurerBuilder = new ServiceProviderBuilder(objectPostProcessor, beanFactory, beanRegistry());
        securityConfigurerBuilder.setSharedObject(ParserPool.class, ParserPoolHolder.getPool());
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerImpl.class, (WebSSOProfileConsumerImpl) webSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(ServiceProviderEndpoints.class, new ServiceProviderEndpoints());
        securityConfigurerBuilder.setSharedObject(ResourceLoader.class, resourceLoader);
        securityConfigurerBuilder.setSharedObject(SAMLSSOProperties.class, sAMLSsoProperties);
        securityConfigurerBuilder.setSharedObject(ExtendedMetadata.class, extendedMetadata);
        securityConfigurerBuilder.setSharedObject(BeanRegistry.class, beanRegistry());
        securityConfigurerBuilder.setSharedObject(SAMLAuthenticationProvider.class, samlAuthenticationProvider);
        securityConfigurerBuilder.setSharedObject(SAMLContextProvider.class, samlContextProvider);
        securityConfigurerBuilder.setSharedObject(KeyManager.class, keyManager);
        securityConfigurerBuilder.setSharedObject(MetadataManager.class, metadataManager);
        securityConfigurerBuilder.setSharedObject(MetadataGenerator.class, metadataGenerator);
        securityConfigurerBuilder.setSharedObject(SAMLProcessor.class, samlProcessor);
        securityConfigurerBuilder.setSharedObject(WebSSOProfile.class, webSSOProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileECPImpl.class, ecpProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileHoKImpl.class, hokWebSSOProfile);
        securityConfigurerBuilder.setSharedObject(SingleLogoutProfile.class, sloProfile);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumer.class, webSSOProfileConsumer);
        securityConfigurerBuilder.setSharedObject(WebSSOProfileConsumerHoKImpl.class, hokWebSSOProfileConsumer);

        //To keep track of which beans were present in the Spring Context and which not, we register them in a
        //BeanRegistry bean. A custom inner type of this class.
        markBeansAsRegistered(securityConfigurerBuilder.getSharedObjects());
        serviceProviderBuilderHolder().setBuilder(securityConfigurerBuilder);
    }

    /**
     * For each object present in the map, register them in the bean registry.
     *
     * @param sharedObjects the objects to register.
     */
    private void markBeansAsRegistered(Map<Class<?>, Object> sharedObjects) {
        sharedObjects.entrySet()
                .forEach(entry -> beanRegistry().addRegistered(entry.getKey(), entry.getValue()));
    }

    /**
     * {@link BeanRegistry} bean registration. Used to store registered  and singleton beans, the latter
     * are created within the bounds of this plugin and some need to be exposed as beans.
     *
     * @return the {@link BeanRegistry}
     */
    @Bean
    public BeanRegistry beanRegistry() {
        return new BeanRegistry(beanFactory);
    }

}
