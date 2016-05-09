package com.github.ulisesbocchio.spring.boot.security.saml.util;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Utilities to overcome functional limitations.
 *
 * @author Ulises Bocchio
 */
public class FunctionalUtils {
    public static <T, E extends Throwable> Consumer<T> unchecked(CheckedConsumer<T, E> consumer) {
        return t -> {
            try {
                consumer.accept(t);
            } catch (Throwable e) {
                RuntimeException r;
                if (e instanceof RuntimeException) {
                    r = (RuntimeException) e;
                } else {
                    r = new RuntimeException(e);
                }
                throw r;
            }
        };
    }

    public static <T, R, E extends Throwable> Function<T, R> uncheckedFunction(CheckedFunction<T, R, E> function) {
        return t -> {
            try {
                return function.apply(t);
            } catch (Throwable e) {
                RuntimeException r;
                if (e instanceof RuntimeException) {
                    r = (RuntimeException) e;
                } else {
                    r = new RuntimeException(e);
                }
                throw r;
            }
        };
    }

    @FunctionalInterface
    public interface CheckedConsumer<T, E extends Throwable> {
        void accept(T t) throws E;
    }

    @FunctionalInterface
    public interface CheckedFunction<T, R, E extends Throwable> {
        R apply(T t) throws E;
    }
}
