package com.github.ulisesbocchio.demo;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAML2Sso;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderConfigurerAdapter;
import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderSecurityBuilder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

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
			super.configure(serviceProvider);
		}
	}
}
