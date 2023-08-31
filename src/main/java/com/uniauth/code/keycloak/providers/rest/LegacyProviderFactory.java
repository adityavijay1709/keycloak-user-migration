package com.uniauth.code.keycloak.providers.rest;

import com.uniauth.code.keycloak.providers.rest.remote.UserModelFactory;
//import com.uniauth.code.keycloak.providers.rest.rest.CustomUserStorageProviderFactory;
import com.uniauth.code.keycloak.providers.rest.rest.RestUserService;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import javax.ws.rs.client.ClientBuilder;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

public class LegacyProviderFactory implements UserStorageProviderFactory<LegacyProvider> {

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ConfigurationProperties.getConfigProperties();
    }

    @Override
    public LegacyProvider create(KeycloakSession session, ComponentModel model) {
        UserProvider userProvider = session.userStorageManager();

        try {
            Field field = userProvider.getClass().getSuperclass().getDeclaredField("STORAGE_PROVIDER_DEFAULT_TIMEOUT");
            field.setAccessible(true);
            Field modifiers = field.getClass().getDeclaredField("modifiers");
            modifiers.setAccessible(true);
            modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
            field.set(userProvider, 120000L);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
        UserModelFactory userModelFactory = new UserModelFactory(session, model);
        RestUserService restService = new RestUserService(model, ClientBuilder.newClient());
        return new LegacyProvider(session, restService, userModelFactory, model);
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        UserProvider userProvider = session.userStorageManager();

        try {
            Field field = userProvider.getClass().getSuperclass().getDeclaredField("STORAGE_PROVIDER_DEFAULT_TIMEOUT");
            field.setAccessible(true);
            Field modifiers = field.getClass().getDeclaredField("modifiers");
            modifiers.setAccessible(true);
            modifiers.setInt(field, field.getModifiers() & ~Modifier.FINAL);
            field.set(userProvider, 120000L);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public String getId() {
        return ConfigurationProperties.PROVIDER_NAME;
    }
}
