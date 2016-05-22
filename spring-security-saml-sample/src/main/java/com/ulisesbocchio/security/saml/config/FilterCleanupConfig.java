package com.ulisesbocchio.security.saml.config;

import com.google.common.collect.ImmutableSet;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Set;

/**
 * @author Ulises Bocchio
 */
@Configuration
public class FilterCleanupConfig {
    @Bean
    public static BeanDefinitionRegistryPostProcessor removeUnwantedAutomaticFilterRegistration() {
        return new BeanDefinitionRegistryPostProcessor() {
            @Override
            public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
            }

            @Override
            public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
                DefaultListableBeanFactory beanFactory = (DefaultListableBeanFactory) bf;
                Set<String> filtersToDisable = ImmutableSet.of("samlEntryPoint", "samlFilter", "samlIDPDiscovery", "metadataDisplayFilter",
                        "samlWebSSOHoKProcessingFilter", "samlWebSSOProcessingFilter",
                        "samlLogoutProcessingFilter", "samlLogoutFilter", "metadataGeneratorFilter");
                Arrays.stream(beanFactory.getBeanNamesForType(javax.servlet.Filter.class))
                        .filter(filtersToDisable::contains)
                        .forEach(name -> {
                            BeanDefinition definition = BeanDefinitionBuilder
                                    .genericBeanDefinition(FilterRegistrationBean.class)
                                    .setScope(BeanDefinition.SCOPE_SINGLETON)
                                    .addConstructorArgReference(name)
                                    .addConstructorArgValue(new ServletRegistrationBean[]{})
                                    .addPropertyValue("enabled", false)
                                    .getBeanDefinition();
                            beanFactory.registerBeanDefinition(name + "FilterRegistrationBean", definition);
                        });
            }
        };
    }
}
