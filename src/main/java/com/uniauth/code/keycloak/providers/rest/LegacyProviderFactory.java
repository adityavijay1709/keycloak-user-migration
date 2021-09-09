package com.uniauth.code.keycloak.providers.rest;

import com.uniauth.code.keycloak.providers.rest.remote.UserModelFactory;
import com.uniauth.code.keycloak.providers.rest.rest.RestUserService;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import javax.ws.rs.client.ClientBuilder;
import java.util.List;

public class LegacyProviderFactory implements UserStorageProviderFactory<LegacyProvider> {

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ConfigurationProperties.getConfigProperties();
    }

    @Override
    public LegacyProvider create(KeycloakSession session, ComponentModel model) {
        UserModelFactory userModelFactory = new UserModelFactory(session, model);
        RestUserService restService = new RestUserService(model, ClientBuilder.newClient());
        return new LegacyProvider(session, restService, userModelFactory, model);
    }

    @Override
    public String getId() {
        return ConfigurationProperties.PROVIDER_NAME;
    }
}
