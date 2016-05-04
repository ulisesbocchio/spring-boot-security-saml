package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;

/**
 * An {@link ObjectPostProcessor} that calls {@link AutowireCapableBeanFactory#autowireBean(Object)} for every
 * object being post-processed.
 *
 * @author Ulises Bocchio
 */
public class AutowiringObjectPostProcessor implements ObjectPostProcessor<Object> {

    private AutowireCapableBeanFactory beanFactory;

    public AutowiringObjectPostProcessor(AutowireCapableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public Object postProcess(Object object) {
        if (object != null) {
            beanFactory.autowireBean(object);
        }
        return object;
    }
}
