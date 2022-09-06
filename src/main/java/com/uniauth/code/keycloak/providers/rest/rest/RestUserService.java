package com.uniauth.code.keycloak.providers.rest.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private  static Client client;
    private  static String uri;

    public RestUserService(ComponentModel model, Client restEasyClient) {
         uri = model.getConfig().getFirst(ConfigurationProperties.URI_PROPERTY);
        client = restEasyClient;
         boolean tokenAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(ConfigurationProperties.API_TOKEN_ENABLED_PROPERTY));
        if (tokenAuthEnabled) {
            String token = model.getConfig().getFirst(ConfigurationProperties.API_TOKEN_PROPERTY);
            client = registerBearerTokenRequestFilter(restEasyClient, token);
        }
        boolean basicAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_ENABLED_PROPERTY));
        if (basicAuthEnabled) {
            String basicAuthUser = model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_USERNAME_PROPERTY);
            String basicAuthPassword = model.getConfig().getFirst(ConfigurationProperties.API_HTTP_BASIC_PASSWORD_PROPERTY);
            client = registerBasicAuthFilter(restEasyClient, basicAuthUser, basicAuthPassword);
        }

    }
    public RestUserService(){

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

    private RestUserClient buildClient( String uri) {

        ResteasyWebTarget target = (ResteasyWebTarget) this.client.target(uri);
        return target.proxy(RestUserClient.class);
    }

    @Override
    public LegacyUser findByEmail(String email) throws JsonProcessingException {
        return findByUsername(email);
    }

    @Override
    public LegacyUser findByUsername(String username) throws JsonProcessingException {
        RestUserClient r = buildClient(uri+"phone");
        Response response = r.findByPhone(username);
        if (response.getStatus() != 200) {
            r = buildClient(uri+"username");
            response = r.findByUsername(username);
            if (response.getStatus() != 200)
                return null;
        }

        Optional<String> json = Optional.ofNullable(response.readEntity(String.class));
        if(json.get()!=null){
            ObjectMapper mapper = new ObjectMapper();
            LegacyUser legacyUser = mapper.readValue(json.get(), LegacyUser.class);
            LOG.info(legacyUser.toString());
            return legacyUser;
        }
        return null;
    }

    @Override
    public boolean isPasswordValid(String username, String password) {
        RestUserClient r = buildClient(uri+"validate");
        final Response response = r.validatePassword(username, new UserPasswordDto(password));
        LOG.warn("Reponse from isValid:"+response.getStatus());
        return response.getStatus() == 200;
    }
    public static void main(String[] args){
        RestUserService ru = new RestUserService();
        RestUserClient r = ru.buildClient("http://tarun.unicommerce.com:8088/data/user/migration/validate");
        final Response response = r.validatePassword("arunkund@unicom.com", new UserPasswordDto("test"));
        System.out.println(response);
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
        RestUserClient r = buildClient(uri.substring(0, uri.length()-1));
        final Response response = r.updatePassword(updatePasswordDto);
        LOG.info("update password response for: "+email);
        return response.getStatus()==200;
    }
}
