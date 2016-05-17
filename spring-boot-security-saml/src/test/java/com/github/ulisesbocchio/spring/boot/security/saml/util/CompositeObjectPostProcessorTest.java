package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mockito.Answers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.NamedBean;
import org.springframework.security.config.annotation.ObjectPostProcessor;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
@SuppressWarnings("ALL")
public class CompositeObjectPostProcessorTest {
    @Test
    public void postProcess() throws Exception {
        CompositeObjectPostProcessor postProcessor = new CompositeObjectPostProcessor();
        ObjectPostProcessor<Object> postProcessor1 = mock(ObjectPostProcessor.class);
        ObjectPostProcessor<Object> postProcessor2 = mock(ObjectPostProcessor.class);
        ObjectPostProcessor<ObjectPostProcessor<Object>> postProcessor3 = mock(ObjectPostProcessor.class);
        postProcessor.addObjectPostProcessor(postProcessor1);
        postProcessor.addObjectPostProcessor(postProcessor2);

        NamedBean bean = mock(NamedBean.class);;
        when(postProcessor1.postProcess(any())).thenAnswer(this::firstArgument);
        when(postProcessor2.postProcess(any())).thenAnswer(this::firstArgument);

        Object result = postProcessor.postProcess(bean);
        Assertions.assertThat(result).isEqualTo(bean);
        verify(postProcessor1).postProcess(eq(bean));
        verify(postProcessor2).postProcess(eq(bean));
        verify(postProcessor3, never()).postProcess(any());
    }

    public Object firstArgument(InvocationOnMock invocation) {
        return invocation.getArguments()[0];
    }

}