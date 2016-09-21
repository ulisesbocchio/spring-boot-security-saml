package com.github.ulisesbocchio.spring.boot.security.saml.configurer;

import com.github.ulisesbocchio.spring.boot.security.saml.annotation.EnableSAMLSSO;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * @author Ulises Bocchio
 */

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@SpringBootTest(classes = ServiceProviderBuilderTest.ServiceProviderConfiguration.class)
public class ServiceProviderBuilderTest {

    @SpringBootApplication
    @EnableSAMLSSO
    public static class ServiceProviderConfiguration {

        @Configuration
        public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
            @Override
            public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
                // @formatter:off
                serviceProvider
                        .metadataGenerator()
                            .entityId("localhost-demo")
                        .and()
                            .sso()
                                .defaultSuccessURL("/home")
                                .idpSelectionPageURL("/idpselection")
                        .and()
                            .logout()
                                .defaultTargetURL("/")
                        .and()
                            .metadataManager()
                                .metadataLocations("classpath:/idp-metadata.xml")
                                .refreshCheckInterval(0)
                        .and()
                            .extendedMetadata()
                                .idpDiscoveryEnabled(true)
                        .and()
                        .keyManager()
                            .privateKeyDERLocation("classpath:/localhost.key.der")
                            .publicKeyPEMLocation("classpath:/localhost.cert");
                // @formatter:on

            }
        }
    }

    @Test
    public void contextLoads() throws Exception {

    }

}