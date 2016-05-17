package com.github.ulisesbocchio.spring.boot.security.saml.resource;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Ulises Bocchio
 */
public class SpringResourceWrapperOpenSAMLResourceTest {

    private ResourceLoader resourceLoader = new DefaultResourceLoader();
    private org.springframework.core.io.Resource springResource;
    private org.springframework.core.io.Resource springResource_nonExistent;

    @Before
    public void setup() {
        springResource = resourceLoader.getResource("classpath:/localhost.cert");
        springResource_nonExistent = resourceLoader.getResource("classpath:/no.good");
    }

    @Test
    public void constructor() throws Exception {
        Resource resource = new SpringResourceWrapperOpenSAMLResource(springResource);
    }

    @Test(expected = ResourceException.class)
    public void constructor_error() throws Exception {
        Resource resource = new SpringResourceWrapperOpenSAMLResource(springResource_nonExistent);
    }

    @Test
    public void attributes() throws Exception {
        Resource resource = new SpringResourceWrapperOpenSAMLResource(springResource);
        assertThat(resource.getInputStream().available()).isEqualTo(springResource.getInputStream().available());
        assertThat(resource.exists()).isTrue();
        assertThat(resource.getLastModifiedTime()).isEqualByComparingTo(new DateTime(springResource.lastModified()));
        assertThat(resource.getLocation()).isEqualTo(springResource.getURL().toString());
    }

}