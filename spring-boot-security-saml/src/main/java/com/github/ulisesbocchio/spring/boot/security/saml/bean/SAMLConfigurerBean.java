package com.github.ulisesbocchio.spring.boot.security.saml.bean;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurer;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderEndpoints;
import com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.CheckedConsumer;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

import static com.github.ulisesbocchio.spring.boot.security.saml.util.FunctionalUtils.unchecked;

/**
 * Spring Security {@link SecurityConfigurerAdapter} implementation to load the actual SAML configuration into Spring
 * Security.
 * Can be used Standalone as a Spring {@link Bean} in conjunction with {@link WebSecurityConfigurerAdapter}
 * and {@link EnableSAMLSSO} like this:
 * <p>
 * <pre>
 *    {@literal @}SpringBootApplication
 *    {@literal @}EnableSAMLSSO
 *     public class OktaSSODemoApplication2 {
 *
 *        public static void main(String[] args) {
 *            SpringApplication.run(OktaSSODemoApplication2.class, args);
 *        }
 *
 *       {@literal @}Configuration
 *        public static class MvcConfig extends WebMvcConfigurerAdapter {
 *
 *           {@literal @}Override
 *            public void addViewControllers(ViewControllerRegistry registry) {
 *                registry.addViewController("/").setViewName("index");
 *                registry.addViewController("/protected").setViewName("protected");
 *                registry.addViewController("/unprotected/help").setViewName("help");
 *
 *            }
 *        }
 *
 *       {@literal @}Configuration
 *        public static class MyServiceProviderConfig extends WebSecurityConfigurerAdapter {
 *
 *            public MyServiceProviderConfig() {
 *                super(false);
 *            }
 *
 *           {@literal @}Bean
 *            SAMLConfigurerBean saml() {
 *                return new SAMLConfigurerBean();
 *            }
 *
 *           {@literal @}Override
 *            public void configure(WebSecurity web) throws Exception {
 *                super.configure(web);
 *            }
 *
 *           {@literal @}Bean
 *            public AuthenticationManager authenticationManagerBean() throws Exception {
 *                return super.authenticationManagerBean();
 *            }
 *
 *           {@literal @}Override
 *            protected void configure(HttpSecurity http) throws Exception {
 *                // @formatter:off
 *                http.authorizeRequests()
 *                    .antMatchers("/unprotected/**")
 *                    .permitAll()
 *                .and()
 *                    .httpBasic()
 *                    .disable()
 *                    .csrf()
 *                    .disable()
 *                    .anonymous()
 *                .and()
 *                    .apply(saml())
 *                    .serviceProvider()
 *                        .metadataGenerator()
 *                        .entityId("localhost-demo")
 *                        .bindingsSSO("artifact", "post", "paos")
 *                    .and()
 *                       .ecpProfile()
 *                    .and()
 *                        .sso()
 *                        .defaultSuccessURL("/home")
 *                        .idpSelectionPageURL("/idpselection")
 *                    .and()
 *                        .metadataManager()
 *                        .metadataLocations("classpath:/idp-okta.xml")
 *                        .refreshCheckInterval(0)
 *                    .and()
 *                        .extendedMetadata()
 *                        .ecpEnabled(true)
 *                        .idpDiscoveryEnabled(true)//set to false for no IDP Selection page.
 *                    .and()
 *                        .keyManager()
 *                        .privateKeyDERLocation("classpath:/localhost.key.der")
 *                        .publicKeyPEMLocation("classpath:/localhost.cert")
 *                    .and()
 *                .http()
 *                    .authorizeRequests()
 *                    .requestMatchers(saml().endpointsMatcher()).permitAll()
 *                .and()
 *                    .authorizeRequests()
 *                    .anyRequest()
 *                    .authenticated();
 *                // @formatter:on
 *            }
 *        }
 *    }
 * </pre>
 *
 * @author Ulises Bocchio
 */
public class SAMLConfigurerBean extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> implements InitializingBean {

    @Autowired
    private ServiceProviderBuilder serviceProviderBuilder;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public void afterPropertiesSet() throws Exception {
        serviceProviderBuilder.setSharedObject(AuthenticationManager.class, authenticationManager);
    }

    /**
     * Default Constructor to be used withing Dependency Injection Container only.
     */
    public SAMLConfigurerBean() {
    }

    /**
     * Constructor for Standalone initialization.
     *
     * @param serviceProviderBuilder The Service Provider Builder to get SAML configuration from.
     * @param authenticationManager The Authentication Manager to setup Spring Security with.
     */
    public SAMLConfigurerBean(ServiceProviderBuilder serviceProviderBuilder, AuthenticationManager authenticationManager) {
        this.serviceProviderBuilder = serviceProviderBuilder;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Returns The {@link ServiceProviderBuilder} for customization of the SAML Service Provider
     *
     * @return The {@link ServiceProviderBuilder} for customization of the SAML Service Provider
     */
    public ServiceProviderBuilder serviceProvider() {
        return serviceProviderBuilder;
    }

    /**
     * Returns The {@link ServiceProviderBuilder} for customization of the SAML Service Provider
     *
     * @param serviceProviderConfigurers A list {@link ServiceProviderConfigurer} to apply to the {@link
     *                                   ServiceProviderBuilder}
     *                                   before it is returned.
     * @return The {@link ServiceProviderBuilder} for customization of the SAML Service Provider
     */
    public ServiceProviderBuilder serviceProvider(List<ServiceProviderConfigurer> serviceProviderConfigurers) {
        serviceProviderConfigurers.forEach(unchecked(spc -> spc.configure(serviceProvider())));
        return serviceProviderBuilder;
    }

    /**
     * Returns a request {@link RequestMatcher} that matches all the SAML endpoints configured by the user:
     * defaultFailureURL, ssoProcessingURL, ssoHoKProcessingURL, discoveryProcessingURL, idpSelectionPageURL,
     * ssoLoginURL, metadataURL, defaultTargetURL, logoutURL and singleLogoutURL.
     * To be used with {@link HttpSecurity#authorizeRequests()} in this fashion:
     * <p>
     * <pre>
     *     http
     *       .authorizeRequests()
     *       .requestMatchers(samlConfigurerBean.endpointsMatcher())
     *       .permitAll()
     * </pre>
     * <p>
     * So that all the configured URLs can bypass security.
     *
     * @return the {@link RequestMatcher}
     */
    public RequestMatcher endpointsMatcher() {
        ServiceProviderEndpoints endpoints = Optional.of(serviceProviderBuilder)
                .map(builder -> builder.getSharedObject(ServiceProviderEndpoints.class))
                .orElseThrow(() -> new IllegalStateException("Can't find SAML Endpoints"));
        return new LazyEndpointsRequestMatcher(endpoints);
    }

    @Override
    public void setBuilder(HttpSecurity httpSecurity) {
        serviceProviderBuilder.setSharedObject(HttpSecurity.class, httpSecurity);
        super.setBuilder(httpSecurity);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void init(HttpSecurity http) throws Exception {
        serviceProviderBuilder.build();
        SAMLAuthenticationProvider authenticationProvider = serviceProviderBuilder.getSharedObject(SAMLAuthenticationProvider.class);
        SAMLEntryPoint sAMLEntryPoint = serviceProviderBuilder.getSharedObject(SAMLEntryPoint.class);
        CheckedConsumer<HttpSecurity, Exception> httpConsumer = serviceProviderBuilder.getSharedObject(CheckedConsumer.class);

        // @formatter:off
        http
            .exceptionHandling()
            .authenticationEntryPoint(sAMLEntryPoint);
        http
            .logout()
            .disable();
        http.
            authenticationProvider(authenticationProvider);

        if(httpConsumer != null) {
            httpConsumer.accept(http);
        }
        // @formatter:on
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        //http
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(MetadataGeneratorFilter.class), BasicAuthenticationFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(MetadataDisplayFilter.class), MetadataGeneratorFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLEntryPoint.class), MetadataDisplayFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLProcessingFilter.class), SAMLEntryPoint.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLWebSSOHoKProcessingFilter.class), SAMLProcessingFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLLogoutProcessingFilter.class), SAMLWebSSOHoKProcessingFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLDiscovery.class), SAMLLogoutProcessingFilter.class);
        http.addFilterAfter(serviceProviderBuilder.getSharedObject(SAMLLogoutFilter.class), SAMLDiscovery.class);
        // @formatter:on
    }

    private static class LazyEndpointsRequestMatcher implements RequestMatcher {

        private RequestMatcher delegate;
        private final ServiceProviderEndpoints endpoints;

        private LazyEndpointsRequestMatcher(ServiceProviderEndpoints endpoints) {
            this.endpoints = endpoints;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            if (delegate == null) {
                synchronized (this) {
                    if (delegate == null) {
                        delegate = endpoints.getRequestMatcher();
                    }
                }
            }
            return delegate.matches(request);
        }
    }
}
