package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.saml.websso.SingleLogoutProfile;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Ulises Bocchio
 */
public class SingleLogoutProfileConfigurerTest {

    private ServiceProviderBuilder builder;

    @Before
    public void setup() {
        builder = mock(ServiceProviderBuilder.class);
    }

    @Test
    public void init() throws Exception {
        SingleLogoutProfileConfigurer configurer = new SingleLogoutProfileConfigurer();
        configurer.init(builder);
        verify(builder).getSharedObject(eq(SingleLogoutProfile.class));
    }

    @Test
    public void configure() throws Exception {
        SingleLogoutProfileConfigurer configurer = spy(new SingleLogoutProfileConfigurer());
        SingleLogoutProfile profile = mock(SingleLogoutProfile.class);
        when(configurer.createDefaultSingleLogoutProfile()).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(builder).setSharedObject(eq(SingleLogoutProfile.class), eq(profile));
    }

    @Test
    public void configure_forBean() throws Exception {
        SingleLogoutProfileConfigurer configurer = spy(new SingleLogoutProfileConfigurer());
        SingleLogoutProfile profile = mock(SingleLogoutProfile.class);
        when(builder.getSharedObject(SingleLogoutProfile.class)).thenReturn(profile);
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSingleLogoutProfile();
        verify(builder, never()).setSharedObject(any(), any());
        verifyZeroInteractions(profile);
    }

    @Test
    public void configure_forConstructor() throws Exception {
        SingleLogoutProfile profile = mock(SingleLogoutProfile.class);
        SingleLogoutProfileConfigurer configurer = spy(new SingleLogoutProfileConfigurer(profile));
        configurer.init(builder);
        configurer.configure(builder);
        verify(configurer, never()).createDefaultSingleLogoutProfile();
        verify(builder).setSharedObject(SingleLogoutProfile.class, profile);
        verifyZeroInteractions(profile);
    }
}