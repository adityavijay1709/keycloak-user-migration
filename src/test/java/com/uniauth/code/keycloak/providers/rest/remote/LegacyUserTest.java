package com.uniauth.code.keycloak.providers.rest.remote;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LegacyUserTest {

    @Test
    void shouldGetAndSetUsername() {
        LegacyUser user = new LegacyUser();
        String expectedValue = "someValue";
        user.setUsername(expectedValue);
        assertEquals(expectedValue, user.getUsername());
    }

    @Test
    void shouldGetAndSetEmail() {
        LegacyUser user = new LegacyUser();
        String expectedValue = "someValue";
        user.setEmail(expectedValue);
        assertEquals(expectedValue, user.getEmail());
    }

    @Test
    void shouldGetAndSetFirstName() {
        LegacyUser user = new LegacyUser();
        String expectedValue = "someValue";
        user.setFirstName(expectedValue);
        assertEquals(expectedValue, user.getFirstName());
    }

    @Test
    void shouldGetAndSetLastName() {
        LegacyUser user = new LegacyUser();
        String expectedValue = "someValue";
        user.setLastName(expectedValue);
        assertEquals(expectedValue, user.getLastName());
    }

    @Test
    void shouldGetAndSetEnabled() {
        LegacyUser user = new LegacyUser();
        user.setEnabled(true);
        assertTrue(user.isEnabled());
    }

    @Test
    void shouldGetAndSetEmailVerified() {
        LegacyUser user = new LegacyUser();
        user.setEmailVerified(true);
        assertTrue(user.isEmailVerified());
    }

    @Test
    void shouldGetAndSetAttributes() {
        LegacyUser user = new LegacyUser();
        Map<String,List<String>> expectedValue = new HashMap<String,List<String>>() {
            {
                put("attribute1",singletonList("value1"));
            }
        };

        user.setAttributes(expectedValue);
        assertEquals(expectedValue, user.getAttributes());
    }

    @Test
    void shouldGetAndSetRoles() {
        LegacyUser user = new LegacyUser();
        List<String> expectedValue = singletonList("value1");
        user.setRoles(expectedValue);
        assertEquals(expectedValue, user.getRoles());
    }

    @Test
    void shouldGetAndSetGroups() {
        LegacyUser user = new LegacyUser();
        List<String> expectedValue = singletonList("value1");
        user.setGroups(expectedValue);
        assertEquals(expectedValue, user.getGroups());
    }

    @Test
    void shouldGetAndSetRequiredActions() {
        LegacyUser user = new LegacyUser();
        List<String> expectedValue = singletonList("value1");
        user.setRequiredActions(expectedValue);
        assertEquals(expectedValue, user.getRequiredActions());
    }

    @Test
    void testEquals() {
        EqualsVerifier.simple().forClass(LegacyUser.class)
                .verify();
    }
}