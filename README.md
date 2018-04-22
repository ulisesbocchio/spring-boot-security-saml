[![Build Status](https://travis-ci.org/ulisesbocchio/spring-boot-security-saml.svg?branch=master)](https://travis-ci.org/ulisesbocchio/spring-boot-security-saml)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ulisesbocchio/spring-boot-security-saml?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.ulisesbocchio/spring-boot-security-saml/badge.svg?style=plastic)](https://maven-badges.herokuapp.com/maven-central/com.github.ulisesbocchio/spring-boot-security-saml)

# spring-boot-security-saml

This project targets a smooth integration between [spring-security-saml](http://projects.spring.io/spring-security-saml/) and Spring Boot by exposing a set of configurer adapters while dealing with the nitty-gritty and boiler plate of `spring-security-saml` configuration internally.

# Works with
Spring Boot 1.4.0+
Spring Boot 1.5.0+

## Quickstart

1. Add the following maven dependency to your project:

    ```xml
    <dependency>
        <groupId>com.github.ulisesbocchio</groupId>
        <artifactId>spring-boot-security-saml</artifactId>
        <version>1.15</version>
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

#### Using `ServiceProviderConfigurerAdapter`

Configuring your Service Provider through the JAVA DSL is pretty straight forward, and it follows the configurer/adapter/builder style that Spring Security currently has. A specific Interface and Adapter class are provided for the configuration, these are: `ServiceProviderConfigurer` and `ServiceProviderConfigurerAdapter` respectively.
In most scenarios, you should be good with simply extending `ServiceProviderConfigurerAdapter` and overriding the `#configure(ServiceProviderBuilder serviceProvider)` method. This is an example:

```java
@Configuration
public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
    @Override
    public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
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
For more documentation and available options, please see the JavaDoc  of `ServiceProviderBuilder` and read the [Configuration Cookbook](#configuration-cookbook). 

#### Using `WebSecurityConfigurerAdapter`

To accomplish the same configuration as above you can also use the regular Spring Security `WebSecurityConfigurerAdapter` to configure SAML authentication for your application in conjunction with any other security configuration your application may need.
For this, besides creating your regular `WebSecurityConfigurerAdapter` configuration, you'll also need a `bean` of type `SAMLConfigurerBean` that you'll be able to plug into your `WebSecurityConfigurerAdapter`. The following is an example that showcases the
exact same configuration from the previous section:

```java
@Configuration
public static class MyServiceProviderConfig extends WebSecurityConfigurerAdapter {

    @Bean
    SAMLConfigurerBean saml() {
        return new SAMLConfigurerBean();
    }
    
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
            
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.httpBasic()
            .disable()
            .csrf()
            .disable()
            .anonymous()
        .and()
            .apply(saml())
            .serviceProvider()
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
                .publicKeyPEMLocation("classpath:/localhost.cert")
        .http()
            .authorizeRequests()
            .requestMatchers(saml().endpointsMatcher())
            .permitAll()
        .and()
            .authorizeRequests()
            .anyRequest()
            .authenticated();
        // @formatter:on
    }
}
```

This is basically a manual configuration of Spring Security on which the `SAMLConfigurerBean` `bean` is defined and used as argument to `HttpSecurity.apply()` which registers the configurer and returns `ServiceProviderBuilder` for further customization.
The `ServiceProviderBuilder` returned is the same type used in the previous example on the `ServiceProviderConfigurerAdapter.configure` method.
After the `ServiceProviderBuilder` is used, an `http()` method exists to go back the the `HttpSecurity` configuration. In the example, the lines:
 
```java
http() // or just http
    .authorizeRequests()
    .requestMatchers(saml().endpointsMatcher())
    .permitAll()
```

Are required to expose the SAML Service Provider endpoints. The `endpointsMatcher()` method returns a `RequestMatcher` that matches only the `SAML` endpoints and will match any default or customized URLs without you having to specify them twice.

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
         idp:
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
 
All you need on the Java side is the `@EnableSAMLSSO` annotation for the default configuration, although if you wanna define a `ServiceProviderConfigurerAdapter` that's fine too, and you can select which configuration you keep on the DSL side and what you leave on the properties, it's up to you.

If what you need is to use a standard `WebSecurityConfigurerAdapter` to configure SAML and you would like to use properties also, you can do that too.
Using the above properties all you need to do is to apply the `SAMLConfigurerBean` to the `HttpSecurity` and disable security for the SAML endpoints:
 
 ```java
 @Configuration
 public static class MyServiceProviderConfig extends WebSecurityConfigurerAdapter {
 
     @Bean
     SAMLConfigurerBean saml() {
         return new SAMLConfigurerBean();
     }
     
     @Bean
     public AuthenticationManager authenticationManagerBean() throws Exception {
         return super.authenticationManagerBean();
     }
             
     @Override
     public void configure(HttpSecurity http) throws Exception {
         // @formatter:off
         http.httpBasic()
             .disable()
             .csrf()
             .disable()
             .anonymous()
         .and()
             .apply(saml())
         .http()
             .authorizeRequests()
             .requestMatchers(saml().endpointsMatcher())
             .permitAll()
         .and()
             .authorizeRequests()
             .anyRequest()
             .authenticated();
         // @formatter:on
     }
 }
 ```

For a more thorough description of the properties please see JavaDoc of class `SAMLSSOProperties` and `ServiceProviderBuilder`. For configuration examples, see [Configuration Cookbook](#configuration-cookbook).

## Overridable Beans

The Following Bean classes can be overridden when using this plugin. All you gotta do is add a Bean declaration anywhere in your Spring Configuration:


|                   Class Name 	| DSL Version                     	|
|-----------------------------:	|---------------------------------	|
| ExtendedMetadata             	| ---             	                |
| SAMLContextProvider          	| DSLSAMLContextProviderImpl       	|
| SAMLContextProviderLB        	| DSLSAMLContextProviderLB       	|
| KeyManager                   	| ---                             	|
| MetadataManager              	| DSLMetadataManager              	|
| MetadataGenerator            	| DSLMetadataGenerator            	|
| SAMLProcessor                	| ---                	            |
| WebSSOProfileConsumer        	| DSLWebSSOProfileConsumerImpl    	|
| WebSSOProfileConsumerHoKImpl 	| DSLWebSSOProfileConsumerHoKImpl 	|
| WebSSOProfile                	| DSLWebSSOProfileImpl             	|
| WebSSOProfileECPImpl         	| DSLWebSSOProfileECPImpl         	|
| WebSSOProfileHoKImpl         	| DSLWebSSOProfileHoKImpl         	|
| SingleLogoutProfile          	| DSLSingleLogoutProfileImpl       	|
| SAMLAuthenticationProvider   	| DSLSAMLAuthenticationProvider   	|
| SAMLBootstrap                	|  ---                            	|
| ParserPool                	|  ---                            	|
| SAMLLogger                	|  ---                            	|


Due to the fact that **MOST** `spring-security-saml` Bean classes use `@Autowire` to inject dependencies, the second column shows a DSL version of the same type
with `@Autowire` turned off that you can use and populate, or implement your own. The ones that don't have a DSL version is because they don't need one.
The beans are then wired by the plugin instead of relying on autowiring.
Here's a sample of bean override:

```java

@Bean
public SAMLContextProvider mySAMLContextProvider() {
    return new DSLSAMLContextProvider();
}

```

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

In [spring-boot-security-saml-demo-dsl](https://github.com/ulisesbocchio/spring-boot-security-saml-samples/tree/master/spring-boot-security-saml-demo-dsl), [spring-boot-security-saml-demo-props](https://github.com/ulisesbocchio/spring-boot-security-saml-samples/tree/master/spring-boot-security-saml-demo-props) there are working demos of this plugin using the Java DSL style and Configuration Properties style respectively.
Also, checkout [spring-boot-security-saml-demo-okta](https://github.com/ulisesbocchio/spring-boot-security-saml-samples/tree/master/spring-boot-security-saml-demo-okta) for a working demo using [Okta](https://www.okta.com) as IDP.

## Check out the spring-security-saml-sample Sample App

In [spring-security-saml-sample](https://github.com/ulisesbocchio/spring-boot-security-saml-samples/tree/master/spring-security-saml-sample) there's a fully working Spring Boot app integrated with regular Spring Security SAML and several IdPs (SSOCircle, Ping Identity, OKTA, OneLogin). In this sample you can check the amount of configuration required to integrate `spring-security-saml` with Spring Boot.

## Configuration Cookbook
These examples are intended to cover some usual Spring Security SAML configuration scenarios through this plugin to showcase the dynamics of the new configuration style. It is not meant as extensive documentation of Spring Security SAML or the SAML 2.0 standard. For documentation regarding Spring Security SAML and SAML 2.0 please see [Further Documentation](#further-documentation) section.

### Configure your application behind a load balancer

In order to successfully redirect to the appropriate URLs when having your Spring Boot application behind a Load Balancer `spring-security-saml` provides an alternate `SAMLContextProviderLB`.
This bean can be configured through the DSL and config properties as of `spring-boot-security-saml:1.12` like this:

```java
@Configuration
    public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {

        @Override
        public void configure(ServiceProviderBuilder serviceProvider) throws Exception {

            serviceProvider
                .metadataGenerator()
                .entityId("localhost-demo")
            .and()
                .sso()
                .defaultSuccessURL("/home")
                .idpSelectionPageURL("/idpselection")
            .and()
                .logout()
                .defaultTargetURL("/")
            .and()
                .metadataManager()
                .metadataLocations("classpath:/idp-ssocircle.xml")
                .refreshCheckInterval(0)
            .and()
                .extendedMetadata()
                .idpDiscoveryEnabled(true)
            .and()
                .keyManager()
                .privateKeyDERLocation("classpath:/localhost.key.der")
                .publicKeyPEMLocation("classpath:/localhost.cert")
            .and()
                .samlContextProviderLb()
                .scheme("https")
                .contextPath("/")
                .serverName("www.example.com")
                .serverPort(443)
                .includeServerPortInRequestURL(false);

        }
    }
``` 
Or using the properties:

```properties
saml.sso.context-provider.lb.context-path=/
saml.sso.context-provider.lb.include-server-port-in-request-url=false
saml.sso.context-provider.lb.scheme=https
saml.sso.context-provider.lb.server-name=www.example.com
saml.sso.context-provider.lb.server-port=443
```

### SHA256 Signature

Some IDPs like ADFS require SHA256 message signature. For this you can just override the `SAMLBootstrap` bean like this:
 
```java
public final class CustomSAMLBootstrap extends SAMLBootstrap {
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        super.postProcessBeanFactory(beanFactory);
        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
    }
}
```
```java
@Bean
public static SAMLBootstrap SAMLBootstrap() {
    return new CustomSAMLBootstrap();
}
```

### Custom SAML Message Storage

`spring-security-saml` stores SAML messages in session by default, if you wanna provide your own SAML storage you can provide
a custom `SAMLContextProvider`with a custom `SAMLMessageStorageFactory`.

With DSL:

```java
@Override
public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
    SAMLContextProviderImpl contextProvider = new SAMLContextProviderImpl();
    contextProvider.setStorageFactory(customMessageStorageFactory);
    
    serviceProvider
            .samlContextProvider(contextProvider);
    
    // rest of configuration
}
```

Overriding `SAMLContextProvider` Bean:

```java
@Bean
SAMLContextProvider mySamlContextProvider(SAMLMessageStorageFactory messageStorageFactory) {
    DSLSAMLContextProviderImpl contextProvider = new DSLSAMLContextProviderImpl();
    contextProvider.setStorageFactory(messageStorageFactory);
    return contextProvider;
}
```

### Configure Bindings

You may wanna set the bindings to use with Your IDP, this is how you can do it through the DSL:

```java
@Override
public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
    WebSSOProfileOptions profileOptions = new WebSSOProfileOptions();
    //POST Bindings
    profileOptions.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    //REDIRECT Bindings
    profileOptions.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    
    serviceProvider
            .sso()
            .profileOptions(profileOptions);
    
    // rest of configuration
}
```

### Static SP Metadata

You may wanna define your Service Provider Metadata statically. Usually there's no reason to do that since the SP metada configuration API through the DSL is pretty rich and
is generated based on specified URLs and so on. But in case this is the way you prefer to setup your SP. Here's a sample config on how you can accomplish that:

```java
@Configuration
public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {
    @Override
    public void configure(ServiceProviderBuilder serviceProvider) throws Exception {
        // @formatter:off
        serviceProvider
            .metadataGenerator()
            .entityId("localhost-demo")
        .and()
            .sso()
            .defaultSuccessURL("/home")
            .idpSelectionPageURL("/idpselection")
        .and()
            .logout()
            .defaultTargetURL("/")
        .and()
            .metadataManager()
            .metadataLocations("classpath:/idp-ssocircle.xml")
            .localMetadataLocation("classpath:/sp-ssocircle.xml")
            .refreshCheckInterval(0)
        .and()
            .extendedMetadata()
            .idpDiscoveryEnabled(true)
        .and()
            .localExtendedMetadata()
            .securityProfile("metaiop")
            .sslSecurityProfile("pkix")
            .signMetadata(true)
            .signingKey("localhost")
            .encryptionKey("localhost")
            .requireArtifactResolveSigned(false)
            .requireLogoutRequestSigned(false)
            .idpDiscoveryEnabled(true)
        .and()
            //This Keystore contains also the public key of idp.ssocircle.com
            .keyManager()
            .storeLocation("classpath:/localhost.jks")
            .storePass("foobar")
            .defaultKey("localhost")
            .keyPassword("localhost", "foobar");
        // @formatter:on
    }
}
```

The part of the configuration that's specifically for static local metadata are `serviceProvider.metadataManager().localMetadataLocaltion("sp-ssocircle.xml")`
and the options specified in `serviceProvider.localExtendedMetadata()`. Notice that when specifying this options, `MetadataGeneratorFilter` is no longer used, since the
Service Provider metadata is specified statically. The endpoint `/saml/metadata` will then display the contents of the specified static metadata file.

### Generate a Self Signed Private/Public key pair in DER/PEM format

```bash
# KEY AND CERT
openssl genrsa -out localhost.key 2048
openssl req -new -x509 -key localhost.key -out localhost.pem -days 3650 -subj /CN=localhost
# PEM KEY to DER
openssl pkcs8 -topk8 -inform PEM -outform DER -in  localhost.key -out  localhost.key.der -nocrypt
```

### Add your own `SAMLUserDetailsService`

In order to add a custom `SAMLUserDetailsService` simply use the `authenticationProvider()` builder from the `ServiceProviderBuilder` DSL:

```java
    @Configuration
    public static class MyServiceProviderConfig extends ServiceProviderConfigurerAdapter {

        @Override
        public void configure(ServiceProviderBuilder serviceProvider) throws Exception {

            serviceProvider
                .authenticationProvider()
                .userDetailsService(new MySAMLUserDetailsService());

        }
    }
```
Or simply add a bean definition for a `SAMLUserDetailsService` implementation:

```java
@Bean
public SAMLUserDetailsService mySamlUserDetailsService() {
    return new MySAMLUserDetailsService();
}
```

## Further Documentation

For configuration specifics about Spring Security SAML please visit their [Documentation Reference](http://docs.spring.io/spring-security-saml/docs/1.0.x/reference/html/).
For SAML 2.0 documentation these are good starting points:
- [SAML Specification](http://saml.xml.org/saml-specifications)
- [SAML 2.0 Wikipedia](https://en.wikipedia.org/wiki/SAML_2.0)
- [Ping Identity's article about SAML](https://www.pingidentity.com/en/resources/articles/saml.html)

# Credits
Special thanks to:
* [@vdenotaris](https://github.com/vdenotaris) for [his original work](https://github.com/vdenotaris/spring-boot-security-saml-sample) on creating a sample `spring-boot` app with `spring-security-saml` that inspired this plugin.
* [@vschafer](https://github.com/vschafer) for creating [`spring-security-saml`](http://projects.spring.io/spring-security-saml/). Without his work, this plugin woudn't be possible.
* [@rwinch](https://github.com/rwinch), whose kind advice and [`spring-security-saml-dsl`](https://github.com/spring-projects/spring-security-saml-dsl) inspired this plugin.
* The Spring Team, for creating amazing open source software.

# License
Lincensed under [MIT License](http://opensource.org/licenses/MIT)
