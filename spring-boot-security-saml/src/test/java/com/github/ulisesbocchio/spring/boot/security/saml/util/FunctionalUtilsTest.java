package com.github.ulisesbocchio.spring.boot.security.saml.util;

import org.assertj.core.api.Assertions;
import org.junit.Test;

import java.io.IOException;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * @author Ulises Bocchio
 */
public class FunctionalUtilsTest {
    @Test
    public void unchecked() throws Exception {
        Consumer<String> consu = FunctionalUtils.unchecked(this::unsafeConsumer);
        consu.accept("pepe");
    }

    @Test
    public void uncheckedFailure() throws Exception {
        Consumer<String> consu = FunctionalUtils.unchecked(this::unsafeThrowingConsumer);
        try {
            consu.accept("pepe");
            fail();
        } catch (Exception e) {
            assertThat(e).hasCauseExactlyInstanceOf(IOException.class);
        }
    }

    public void unsafeConsumer(String msg) throws Exception {
    }

    public void unsafeThrowingConsumer(String msg) throws IOException {
        throw new IOException("Pronto");
    }

    @Test
    public void uncheckedFunction() throws Exception {
        Function<String, String> consu = FunctionalUtils.uncheckedFunction(this::unsafeFunction);
        String f = consu.apply("pepe");
        assertThat(f).isEqualTo("Pronto");
    }

    @Test
    public void uncheckedFunctionFailure() throws Exception {
        Function<String, String> consu = FunctionalUtils.uncheckedFunction(this::unsafeThrowingFunction);
        try {
            consu.apply("pepe");
            fail();
        } catch (Exception e) {
            assertThat(e).hasCauseExactlyInstanceOf(IOException.class);
        }
    }

    public String unsafeFunction(String msg) throws Exception {
        return "Pronto";
    }

    public String unsafeThrowingFunction(String msg) throws IOException {
        throw new IOException("Pronto");
    }

}