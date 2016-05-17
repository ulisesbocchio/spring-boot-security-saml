package com.github.ulisesbocchio.spring.boot.security.saml.user;

import org.junit.Test;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Ulises Bocchio
 */
public class SAMLUserDetailsTest {

    @Test
    public void testAttributes() {
        SAMLCredential samlCredential = mock(SAMLCredential.class);
        NameID nameId = mock(NameID.class);
        when(samlCredential.getNameID()).thenReturn(nameId);
        Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn("attr");
        when(samlCredential.getAttributes()).thenReturn(Collections.singletonList(attribute));
        when(samlCredential.getAttribute("attr")).thenReturn(attribute);
        when(samlCredential.getAttributeAsString("attr")).thenReturn("value");
        when(samlCredential.getAttributeAsStringArray("attr")).thenReturn(new String[]{"value"});
        when(nameId.toString()).thenReturn(NameID.UNSPECIFIED);
        SAMLUserDetails details = new SAMLUserDetails(samlCredential);
        assertThat(details.getPassword()).isEmpty();
        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_USER");
        assertThat(details.getAttribute("attr")).isEqualTo("value");
        assertThat(details.getAttributeArray("attr")).containsExactly("value");
        assertThat(details.getAttributes()).containsOnlyKeys("attr").containsValue("value");
        assertThat(details.getAttributesArrays()).containsOnlyKeys("attr");
        assertThat(details.getAttributesArrays().get("attr")).containsExactly("value");
    }

}