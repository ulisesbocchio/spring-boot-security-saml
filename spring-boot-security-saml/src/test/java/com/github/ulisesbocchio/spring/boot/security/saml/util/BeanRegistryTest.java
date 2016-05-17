package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.junit.Test;
import org.springframework.beans.factory.NamedBean;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class BeanRegistryTest {
    @Test
    public void addSingleton() throws Exception {
        DefaultListableBeanFactory beanFactory = mock(DefaultListableBeanFactory.class);
        BeanRegistry beanRegistry = new BeanRegistry(beanFactory);
        NamedBean bean = mock(NamedBean.class);
        when(bean.getBeanName()).thenReturn("grillo");
        beanRegistry.addSingleton("pepe", bean);
        assertThat(beanRegistry.getSingletons()).containsOnlyKeys("pepe").containsValue(bean);
        assertThat(beanRegistry.getRegisteredBeans()).isEmpty();
        assertThat(beanRegistry.isRegistered(bean)).isFalse();
        beanRegistry.destroy();
        verify(beanFactory).destroySingleton(eq("pepe"));
    }

    @Test
    public void addRegistered() throws Exception {
        DefaultListableBeanFactory beanFactory = mock(DefaultListableBeanFactory.class);
        BeanRegistry beanRegistry = new BeanRegistry(beanFactory);
        NamedBean bean = mock(NamedBean.class);
        when(bean.getBeanName()).thenReturn("grillo");
        beanRegistry.addRegistered(bean.getClass(), bean);
        assertThat(beanRegistry.getSingletons()).isEmpty();
        assertThat(beanRegistry.getRegisteredBeans()).containsOnlyKeys(bean.getClass()).containsValue(bean);
        assertThat(beanRegistry.isRegistered(bean)).isTrue();
        beanRegistry.destroy();
        verify(beanFactory, never()).destroySingleton(any());
    }

    @Test
    public void addRegistered1() throws Exception {
        DefaultListableBeanFactory beanFactory = mock(DefaultListableBeanFactory.class);
        BeanRegistry beanRegistry = new BeanRegistry(beanFactory);
        NamedBean bean = mock(NamedBean.class);
        when(bean.getBeanName()).thenReturn("grillo");
        beanRegistry.addRegistered(bean);
        assertThat(beanRegistry.getSingletons()).isEmpty();
        assertThat(beanRegistry.getRegisteredBeans()).containsOnlyKeys(bean.getClass()).containsValue(bean);
        assertThat(beanRegistry.isRegistered(bean)).isTrue();
        beanRegistry.destroy();
        verify(beanFactory, never()).destroySingleton(any());
    }
}