package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.junit.Test;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Ulises Bocchio
 */
public class AutowiringObjectPostProcessorTest {
    @Test
    public void postProcess() throws Exception {
        AutowireCapableBeanFactory beanFactory = mock(AutowireCapableBeanFactory.class);
        AutowiringObjectPostProcessor postProcessor = new AutowiringObjectPostProcessor(beanFactory);
        Object obj = postProcessor.postProcess(this);
        assertThat(obj).isEqualTo(this);
        verify(beanFactory).autowireBean(eq(this));
    }

    @Test
    public void postProcess_null() throws Exception {
        AutowireCapableBeanFactory beanFactory = mock(AutowireCapableBeanFactory.class);
        AutowiringObjectPostProcessor postProcessor = new AutowiringObjectPostProcessor(beanFactory);
        Object obj = postProcessor.postProcess(null);
        assertThat(obj).isNull();
        verify(beanFactory, never()).autowireBean(any());
    }

}