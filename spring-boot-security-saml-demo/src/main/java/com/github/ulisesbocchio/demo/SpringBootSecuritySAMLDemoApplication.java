package com.github.ulisesbocchio.demo;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAML2Sso;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.resource.SpringResourceWrapperOpenSAMLResource;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.RequiredValidUntilFilter;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.saml2.metadata.provider.SignatureValidationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Timer;

@SpringBootApplication
@EnableSAML2Sso
public class SpringBootSecuritySAMLDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootSecuritySAMLDemoApplication.class, args);
	}

	@Configuration
	public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			super.configure(http);
		}

		@Override
		public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
			serviceProvider
					.metadataManager()
                    .metadataFilter(new RequiredValidUntilFilter())
					.metadataProvider(metadataProvider())
			.and()
			.authenticationProvider()
					.excludeCredential(false)
					.forcePrincipalAsString(false);
		}

        @Value("classpath:/idp-ssocircle.xml")
        Resource ssoCircleMetadata;

        //Metadata providers are converted to ExtendedMetadataProvider automatically, and injected the ParserPool object
        @Bean
        MetadataProvider metadataProvider() throws Exception {
            Timer refreshTimer = new Timer(true);
            return new ResourceBackedMetadataProvider(refreshTimer, new SpringResourceWrapperOpenSAMLResource(ssoCircleMetadata));
        }
	}
}
