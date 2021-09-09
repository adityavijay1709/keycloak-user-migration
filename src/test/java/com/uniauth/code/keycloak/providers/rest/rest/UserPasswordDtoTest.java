package com.uniauth.code.keycloak.providers.rest.rest;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserPasswordDtoTest {

    @Test
    void shouldConstructWithPassword() {
        String password = "somePassword";
        UserPasswordDto dto = new UserPasswordDto(password);
        assertEquals(password, dto.getPassword());
    }

    @Test
    void shouldSetAndGetPassword() {
        String password = "somePassword";
        UserPasswordDto dto = new UserPasswordDto();
        dto.setPassword(password);
        assertEquals(password, dto.getPassword());
    }

    @Test
    void equalsContract() {
        EqualsVerifier.simple().forClass(UserPasswordDto.class)
                .verify();
    }
}