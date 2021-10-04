package com.uniauth.code.keycloak.providers.rest.rest;

import com.uniauth.code.keycloak.providers.rest.ConfigurationProperties;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUser;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUserService;
import java.util.Optional;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.internal.BasicAuthentication;
import org.keycloak.component.ComponentModel;

public class RestUserService implements LegacyUserService {
    private static final Logger LOG = Logger.getLogger(RestUserService.class);

    private final RestUserClient client;

    public RestUserService(ComponentModel model, Client restEasyClient) {
        String uri = model.getConfig().getFirst(ConfigurationProperties.URI_PROPERTY);
        boolean tokenAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(ConfigurationProperties.API_TOKEN_ENABLED_PROPERTY));
        if (tokenAuthEnabled) {
            String token = model.getConfig().getFirst(ConfigurationProperties.API_TOKEN_PROPERTY);
            registerBearerTokenRequestFilter(restEasyClient, token);
        }
        boolean basicAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_ENABLED_PROPERTY));
        if (basicAuthEnabled) {
            String basicAuthUser = model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_USERNAME_PROPERTY);
            String basicAuthPassword = model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_PASSWORD_PROPERTY);
            registerBasicAuthFilter(restEasyClient, basicAuthUser, basicAuthPassword);
        }
        this.client = buildClient(restEasyClient, uri);
    }

    private Client registerBasicAuthFilter(Client restEasyClient, String basicAuthUser, String basicAuthPassword) {
        if (basicAuthUser != null
                && !basicAuthUser.isEmpty()
                && basicAuthPassword != null
                && !basicAuthPassword.isEmpty()) {
            restEasyClient.register(new BasicAuthentication(basicAuthUser, basicAuthPassword));
        }
        return restEasyClient;
    }

    private Client registerBearerTokenRequestFilter(Client restEasyClient, String token) {
        if (token != null && !token.isEmpty()) {
            restEasyClient.register(new BearerTokenRequestFilter(token));
        }
        return restEasyClient;
    }

    private RestUserClient buildClient(Client restEasyClient, String uri) {

        ResteasyWebTarget target = (ResteasyWebTarget) restEasyClient.target(uri);
        return target.proxy(RestUserClient.class);
    }

    @Override
    public Optional<LegacyUser> findByEmail(String email) {
        return findByUsername(email);
    }

    @Override
    public Optional<LegacyUser> findByUsername(String username) {
        final Response response = client.findByPhone(username);
        if (response.getStatus() != 200) {
            return Optional.empty();
        }

        LOG.info("findByUsername: "+username+" response: "+response.readEntity(LegacyUser.class).toString());
        return Optional.ofNullable(response.readEntity(LegacyUser.class));
    }

    @Override
    public boolean isPasswordValid(String username, String password) {
        final Response response = client.validatePassword(username, new UserPasswordDto(password));
        return response.getStatus() == 200;
    }

    /**
     * Update password on external Store
     *
     * @param email
     * @param password
     */
    @Override public boolean updatePassword(String email, String password) {
        UpdatePasswordDto updatePasswordDto = new UpdatePasswordDto();
        updatePasswordDto.setEmail(email);
        updatePasswordDto.setPassword(password);
        updatePasswordDto.setConfirmPassword(password);
        final Response response = client.updatePassword(updatePasswordDto);
        LOG.info("update password response for: "+email+" : "+response.getEntity().toString());
        return response.getStatus()==200;
    }
}
