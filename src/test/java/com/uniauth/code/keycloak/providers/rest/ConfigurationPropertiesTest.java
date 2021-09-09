package com.uniauth.code.keycloak.providers.rest;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ConfigurationPropertiesTest {

    @Test
    void shouldGetConfigProperties() {
        List<ProviderConfigProperty> result = ConfigurationProperties.getConfigProperties();
        assertNotNull(result);
    }
}