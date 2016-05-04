package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.springframework.core.GenericTypeResolver;
import org.springframework.security.config.annotation.ObjectPostProcessor;

import java.util.ArrayList;
import java.util.List;

/**
 * An {@link ObjectPostProcessor} that delegates work to numerous
 * {@link ObjectPostProcessor} implementations.
 *
 * @author Rob Winch
 */
public final class CompositeObjectPostProcessor implements ObjectPostProcessor<Object> {
    private List<ObjectPostProcessor<? extends Object>> postProcessors = new ArrayList<>();

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Object postProcess(Object object) {
        for (ObjectPostProcessor opp : postProcessors) {
            Class<?> oppClass = opp.getClass();
            Class<?> oppType = GenericTypeResolver.resolveTypeArgument(oppClass,
                    ObjectPostProcessor.class);
            if (oppType == null || oppType.isAssignableFrom(object.getClass())) {
                object = opp.postProcess(object);
            }
        }
        return object;
    }

    /**
     * Adds an {@link ObjectPostProcessor} to use
     * @param objectPostProcessor the {@link ObjectPostProcessor} to add
     * @return true if the {@link ObjectPostProcessor} was added, else false
     */
    public boolean addObjectPostProcessor(
            ObjectPostProcessor<? extends Object> objectPostProcessor) {
        return this.postProcessors.add(objectPostProcessor);
    }
}
