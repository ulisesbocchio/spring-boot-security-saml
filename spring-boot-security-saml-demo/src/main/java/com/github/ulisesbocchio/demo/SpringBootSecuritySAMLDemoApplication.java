package com.github.ulisesbocchio.demo;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSso;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@EnableSAMLSso
public class SpringBootSecuritySAMLDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecuritySAMLDemoApplication.class, args);
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
        public void configure(HttpSecurity http) throws Exception {
            super.configure(http);
        }

        @Override
        public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
            serviceProvider.sso()
                    .defaultSuccessURL("/home")
                    .idpSelectionPageURL("/idpselection");
            serviceProvider.logout()
                    .defaultTargetURL("/");
            serviceProvider.metadataManager()
                    .metadataLocations("classpath:/idp-ssocircle.xml");
        }
    }
}
