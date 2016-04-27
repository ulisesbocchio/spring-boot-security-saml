package com.github.ulisesbocchio.spring.boot.security.saml.util;

import lombok.SneakyThrows;

import java.util.function.Consumer;

/**
 * @author Ulises Bocchio
 */
public class FunctionalUtils {
    public static <T, E extends Throwable> Consumer<T> unchecked(CheckedConsumer<T, E> consumer) {
        return new Consumer<T>() {
            @Override
            @SneakyThrows
            public void accept(T t) {
                consumer.accept(t);
            }
        };
    }

    @FunctionalInterface
    public interface CheckedConsumer<T, E extends Throwable> {
        void accept(T t) throws E;
    }
}
