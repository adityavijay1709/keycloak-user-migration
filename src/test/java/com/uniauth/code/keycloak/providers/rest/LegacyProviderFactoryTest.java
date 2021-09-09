package com.uniauth.code.keycloak.providers.rest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LegacyProviderFactoryTest {

    private LegacyProviderFactory legacyProviderFactory;

    @Mock
    private KeycloakSession session;

    @Mock
    private ComponentModel model;

    @BeforeEach
    void setUp() {
        legacyProviderFactory = new LegacyProviderFactory();
    }

    @Test
    void getConfigProperties() {
        assertEquals(ConfigurationProperties.getConfigProperties(), legacyProviderFactory.getConfigProperties());
    }

    @Test
    void create() {
        final MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(ConfigurationProperties.URI_PROPERTY, "http://localhost");
        when(model.getConfig())
                .thenReturn(config);
        LegacyProvider provider = legacyProviderFactory.create(session, model);
        assertNotNull(provider);
    }

    @Test
    void getId() {
        assertEquals(ConfigurationProperties.PROVIDER_NAME, legacyProviderFactory.getId());
    }
}