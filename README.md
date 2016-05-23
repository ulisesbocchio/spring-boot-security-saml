[![Build Status](https://travis-ci.org/ulisesbocchio/spring-boot-security-saml.svg?branch=master)](https://travis-ci.org/ulisesbocchio/spring-boot-security-saml)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ulisesbocchio/spring-boot-security-saml?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.ulisesbocchio/spring-boot-security-saml/badge.svg?style=plastic)](https://maven-badges.herokuapp.com/maven-central/com.github.ulisesbocchio/spring-boot-security-saml)

# spring-boot-security-saml

This project targets a smooth integration between [spring-security-saml](http://projects.spring.io/spring-security-saml/) and Spring Boot by exposing a set of configurer adapters while dealing with the nitty-gritty and boiler plate of `spring-security-saml` configuration internally.

## Quickstart

1. Add the following maven dependency to your project:

    ```xml
    <dependency>
        <groupId>com.github.ulisesbocchio</groupId>
        <artifactId>spring-boot-security-saml</artifactId>
        <version>1.0</version>
    </dependency>
    
    ```

2. Add the `@EnableSAMLSSO` annotation to your Spring Boot Application on any `@Configuration` class:

    ```java
    @SpringBootApplication
    @EnableSAMLSSO
    public class ServiceProviderApplication {
        ...
    }
    ```

3. Start configuring your SAML 2.0 Service provider (see [below](#configure-your-saml-20-service-provider)).

## Configure your SAML 2.0 Service Provider

For those familiar with `spring-security-saml` this plugin exposes most of it configuration points through 2 different forms that are fully interchangeable and combine-able except when providing custom implementations and instances.
The two configuration flavors are:

2. [Java DSL](#java-dsl)
1. [Configuration Properties](#configuration-properties)

### Java DSL

Configuring your Service Provider through the JAVA DSL is also pretty straight forward, and it follows the configurer/adapter/builder style that Spring Security currently has. A specific Interface and Adapter class are provided for the configuration, these are: `ServiceProviderConfigurer` and `ServiceProviderConfigurerAdapter` respectively.
In most scenarios, you should be good with simply extending `ServiceProviderConfigurerAdapter` and overriding the `#configure(ServiceProviderSecurityBuilder serviceProvider)` method. This is an example:

```java
@Configuration
public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
    @Override
    public void configure(ServiceProviderSecurityBuilder serviceProvider) throws Exception {
        // @formatter:off
        serviceProvider 
            .metadataGenerator() //(1)
            .entityId("localhost-demo")
        .and()
            .sso() //(2)
            .defaultSuccessURL("/home")
            .idpSelectionPageURL("/idpselection")
        .and()
            .logout() //(3)
            .defaultTargetURL("/")
        .and()
            .metadataManager() //(4)
            .metadataLocations("classpath:/idp-ssocircle.xml")
            .refreshCheckInterval(0)
        .and()
            .extendedMetadata() //(5)
            .idpDiscoveryEnabled(true)
        .and()
            .keyManager() //(6)
            .privateKeyDERLocation("classpath:/localhost.key.der")
            .publicKeyPEMLocation("classpath:/localhost.cert");
        // @formatter:on
    }
}
```

It is not strictly necessary for this class to be a `@Configuration` class, it could also be a Spring Bean. As far as it is exposed in the Application Context, the plugin will pick it up and configure the Service Provider accordingly.
The other two methods in the Configurer/Adapter, `#configure(HttpSecurity http)` and `#configure(WebSecurity web)` allow for in-place customization of Spring Security's `HttpSecurity` and `WebSecurity` objects, without requiring extending other configurers/adapters to be implemented/extended, basically a shortcut.
In the above example, you can see how the following items are specified:

1. The Service Provider entity ID
2. The default success URL (redirect after successful login through the IDP if not saved request present) and a custom IDP Selection page URL for selecting and Identity Provider before login.
3. The default logout URL, basically the URL to be redirected after successful logout.
4. The IDP metadata to be used to send requests to the IDP and validate incoming calls from the IDP, and metadata reflesh interval (0 means never).
5. Enable IDP discovery, so when SAML SSO kicks in, we'll be presented with an IDP selection page before the actual login, (set to false to use default IDP).
6. And we provide a custom private key (DER format) and public cert (PEM format) to be used for signing outgoing requests. (To be configured in the IDP side also).

This configuration is equivalent to the one showcased in the [Configuration Properties](#configuration-properties) section.
For more documentation and available options, please see the JavaDoc  of `ServiceProviderSecurityBuilder` and read the [Configuration Cookbook](#configuration-cookbook). 

### Configuration Properties

Configuring your Service Provider through configuration properties is pretty straight forward and most configurations could be accomplished this way. The two limitations that exists are: You can only configure what is exposed as properties, obviously, and you cannot provide specific implementations or instances of the different Spring Security SAML classes/interfaces. If you need to provide custom implementations of certain types or a more dynamic configuration you'll need to use the [Java DSL](#java-dsl) approach for that configuration, but as expressed before, you can configure as much as you can through properties, while using the DSL configuration for any dynamic or custom implementations configuration. You can mix the two flavors.   
 For a full list of all configuration properties available see [this document](docs/properties/config-properties.md). Not included here to avoid clutter.

The following properties snippet is a sample configuration through `application.yml`.
 
```yaml
 saml:
     sso:
         default-success-url: /home    #(1)
         idp-selection-page-url: /idpSelection    #(2)
         metadata-generator:
             entity-id: localhost-demo    #(3)
         logout:
             default-target-url: /    #(4)
         idps:
             metadata-location: classpath:/idp-ssocircle.xml    #(5) 
         metadata-manager:
             refresh-check-interval: 0    #(6)
         extended-metadata:
             idp-discovery-enabled: true    #(7)
         key-manager:
             private-key-der-location: classpath:/localhost.key.der    #(8)
             public-key-pem-location: classpath:/localhost.cert    #(9)
```
 
 In the above example, you can see how the following items are specified:
 
 1. The default success URL (redirect after successful login through the IDP if not saved request present) and
 2. A custom IDP Selection page URL for selecting and Identity Provider before login.
 3. The Service Provider entity ID
 4. The default logout URL, basically the URL to be redirected after successful logout.
 5. The IDP metadata to be used to send requests to the IDP and validate incoming calls from the IDP,
 6. And metadata reflesh interval (0 means never).
 7. Enable IDP discovery, so when SAML SSO kicks in, we'll be presented with an IDP selection page before the actual login, (set to false to use default IDP).
 8. Provide a custom private key (DER format)
 9. And public cert (PEM format) to be used for signing outgoing requests. (To be configured in the IDP side also).

For a more thorough description of the properties please see JavaDoc of class `SAMLSSOProperties` and `ServiceProviderSecurityBuilder`. For configuration examples, see [Configuration Cookbook](#configuration-cookbook).

## Spring MVC Configuration

No default templates are provided with `spring-boot-security-saml` for IDP selection page, home page, or default logout page. Developers need to configure the desired template engine and make sure that the URLs configured for this plugin are resolvable through Spring MVC.
For instance, the following configuration is used in the Demo apps to specify the index page that is also mapped to the logout page:

```java
@Configuration
public static class MvcConfig extends WebMvcConfigurerAdapter {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");

    }
}
```

In the other hand, `idpSelection.html` and `home.html` under `resources/templates/` in the Demo apps are implicitly defined as view controllers by Spring Boot's Thymeleaf auto-configuration.
For more information on how to configure Spring MVC please visit Spring MVC's [Documentation](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/mvc.html) page and Spring Boot's Web Applications [Documentation](http://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#boot-features-developing-web-applications).

## Check out the spring-boot-security-saml Demo Apps

In [spring-boot-security-saml-demo-dsl](spring-boot-security-saml-demo-dsl), [spring-boot-security-saml-demo-props](spring-boot-security-saml-demo-props) there are working demos of this plugin using the Java DSL style and Configuration Properties style respectively.
Also, checkout [spring-boot-security-saml-demo-okta](spring-boot-security-saml-demo-okta) for a working demo using [Okta](https://www.okta.com) as IDP.

## Check out the spring-security-saml-sample Sample App

In [spring-security-saml-sample](spring-security-saml-sample) there's a fully working Spring Boot app integrated with regular Spring Security SAML and several IdPs (SSOCircle, Ping Identity, OKTA, OneLogin). In this sample you can check the amount of configuration required to integrate `spring-security-saml` with Spring Boot.

## Configuration Cookbook
These examples are intended to cover some usual Spring Security SAML configuration scenarios through this plugin to showcase the dynamics of the new configuration style. It is not meant as extensive documentation of Spring Security SAML or the SAML 2.0 standard. For documentation regarding Spring Security SAML and SAML 2.0 please see [Further Documentation](#further-documentation) section.

*** Coming Soon ***

## Further Documentation

For configuration specifics about Spring Security SAML please visit their [Documentation Reference](http://docs.spring.io/spring-security-saml/docs/1.0.x/reference/html/).
For SAML 2.0 documentation these are good starting points:
- [SAML Specification](http://saml.xml.org/saml-specifications)
- [SAML 2.0 Wikipedia](https://en.wikipedia.org/wiki/SAML_2.0)
- [Ping Identity's article about SAML](https://www.pingidentity.com/en/resources/articles/saml.html)

