package com.github.ulisesbocchio.demo;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@EnableSAMLSSO
public class OktaSSODemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(OktaSSODemoApplication.class, args);
    }

    @Configuration
    public static class MvcConfig extends WebMvcConfigurerAdapter {

        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("/").setViewName("index");
            registry.addViewController("/protected").setViewName("protected");

        }
    }

    @Configuration
    public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
        @Override
        public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
            serviceProvider
                .metadataGenerator()
                .entityId("localhost-demo")
            .and()
                .sso()
                .defaultSuccessURL("/home")
                .idpSelectionPageURL("/idpselection")
            .and()
                .metadataManager()
                .metadataLocations("classpath:/idp-okta.xml")
                .refreshCheckInterval(0)
            .and()
                .extendedMetadata()
                .idpDiscoveryEnabled(true)//set to false for no IDP Selection page.
            .and()
                .keyManager()
                .privateKeyDERLocation("classpath:/localhost.key.der")
                .publicKeyPEMLocation("classpath:/localhost.cert");

        }
    }
}
