package com.github.ulisesbocchio.spring.boot.security.saml.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Strategy for keeping track of registered and singleton beans. Registered are beans that have a Bean Definition in
 * the Spring Context. Singletons are those exposed by this plugin "manually", as a way to overcome certain design
 * flaws in Spring Security SAML. Particularly the fact that most classes have {@link Autowired} annotations, and as
 * they mostly implement {@link InitializingBean}, this plugin overcomes that problem by registering the internally
 * created objects as singletons with the {@link DefaultListableBeanFactory} so they can get autowired before the
 * {@link ObjectPostProcessor} provided by Spring Security calls the {@link InitializingBean#afterPropertiesSet()}
 * method on the beans. This way, the lifecycle of this beans is at most "semi-automatic", and this class provides
 * a destroy mechanism to dispose of those singleton beans that implement {@link DisposableBean}.
 */
@Slf4j
public class BeanRegistry implements DisposableBean {
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
