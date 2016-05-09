package com.github.ulisesbocchio.spring.boot.security.saml.annotation;

import com.github.ulisesbocchio.spring.boot.security.saml.user.SAMLUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;
import java.security.Principal;

/**
 * Synonym of {@link AuthenticationPrincipal}, it allow to inject the Authentication {@link Principal} into Controller
 * classes. In the case of the SAML 2.0 Service Provider, it injects, by default, objects of type {@link SAMLUserDetails}
 *
 * @author Ulises Bocchio
 * @see SAMLUserDetails
 * @see AuthenticationPrincipal
 */
@Target({ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface SAMLUser {
}
