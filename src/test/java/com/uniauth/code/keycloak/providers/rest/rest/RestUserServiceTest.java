package com.uniauth.code.keycloak.providers.rest.rest;

import com.uniauth.code.keycloak.providers.rest.remote.LegacyUser;
import com.uniauth.code.keycloak.providers.rest.ConfigurationProperties;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.internal.BasicAuthentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RestUserServiceTest {

    private RestUserService restUserService;

    @Mock
    private ComponentModel model;

    @Mock
    private RestUserClient client;

    @Mock
    private Client restEasyClient;

    @BeforeEach
    void setUp() {
        String uri = "someUri";
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<String, String>();
        config.putSingle(ConfigurationProperties.URI_PROPERTY, uri);
        ResteasyWebTarget resteasyWebTarget = mock(ResteasyWebTarget.class);

        when(model.getConfig()).thenReturn(config);
        when(restEasyClient.target(uri))
                .thenReturn(resteasyWebTarget);
        when(resteasyWebTarget.proxy(RestUserClient.class))
                .thenReturn(client);

        restUserService = new RestUserService(model, restEasyClient);
    }

    @Test
    void shouldRegisterBasicAuthRequestFilterIfBasicAuthEnabledAndCredentialsNotEmpty() {
        model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_USERNAME_PROPERTY, "someUser");
        model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_PASSWORD_PROPERTY, "somePassword");
        model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_ENABLED_PROPERTY, "true");
        restUserService = new RestUserService(model, restEasyClient);
        ArgumentCaptor<Object> filterCaptor = ArgumentCaptor.forClass(Object.class);

        verify(restEasyClient).register(filterCaptor.capture());

        assertTrue(filterCaptor.getValue() instanceof BasicAuthentication);
    }



    @Nested
    class ShouldNotRegisterBasicAuthRequestFilter {

        @ParameterizedTest
        @CsvSource(
                value = {
                        "someUser,somePassword,false'", // deactivated
                        "someUser,'',true", // activated, password empty
                        "someUser,null,true", // activated, password null
                        "'',somePassword,true", // activated, user empty
                        "null,somePassword,true", // activated, user null
                        "'','',true", // activated, both empty
                        "null,null,true", // activated, both null
                },
                nullValues = {"null"}
        )
        void ifBasicAuthDisabledOrCredentialsEmptyOrNull(String userName, String password, String basicAuthEnabled ) {
            model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_USERNAME_PROPERTY, userName);
            model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_PASSWORD_PROPERTY, password);
            model.getConfig().add(ConfigurationProperties.API_HTTP_BASIC_ENABLED_PROPERTY, basicAuthEnabled);
            restUserService = new RestUserService(model, restEasyClient);

            verify(restEasyClient, never()).register(any());
        }

    }

    @Test
    void shouldRegisterBearerTokenRequestFilterIfTokenAuthEnabledAndTokenNotEmpty() {
        model.getConfig().add(ConfigurationProperties.API_TOKEN_PROPERTY, "someToken");
        model.getConfig().add(ConfigurationProperties.API_TOKEN_ENABLED_PROPERTY, "true");
        restUserService = new RestUserService(model, restEasyClient);
        ArgumentCaptor<Object> filterCaptor = ArgumentCaptor.forClass(Object.class);

        verify(restEasyClient).register(filterCaptor.capture());

        assertTrue(filterCaptor.getValue() instanceof BearerTokenRequestFilter);
    }

    @Nested
    class ShouldNotRegisterBearerTokenRequestFilter {

        @Test
        void ifTokenAuthDisabledAndTokenNotEmpty() {
            model.getConfig().add(ConfigurationProperties.API_TOKEN_PROPERTY, "someToken");
            model.getConfig().add(ConfigurationProperties.API_TOKEN_ENABLED_PROPERTY, "false");
            restUserService = new RestUserService(model, restEasyClient);

            verify(restEasyClient, never()).register(any());
        }

        @ParameterizedTest
        @CsvSource(
                value = {
                        "true,''", // empty value
                        "true,null", // null
                },
                nullValues = {"null"}
        )
        void ifTokenNullOrEmpty(String tokenEnabled, String tokenValue) {
            model.getConfig().add(ConfigurationProperties.API_TOKEN_PROPERTY, tokenValue);
            model.getConfig().add(ConfigurationProperties.API_TOKEN_ENABLED_PROPERTY, tokenEnabled);
            restUserService = new RestUserService(model, restEasyClient);

            verify(restEasyClient, never()).register(any());
        }

    }


    @Test
    void shouldFindByEmail() {
        String email = "someEmail";
        LegacyUser expectedResult = new LegacyUser();
        Response response = mock(Response.class);

        when(client.findByUsername(email))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(200);
        when(response.readEntity(LegacyUser.class))
                .thenReturn(expectedResult);

        Optional<LegacyUser> result = restUserService.findByEmail(email);
        assertTrue(result.isPresent());
        assertEquals(expectedResult, result.get());
    }

    @Test
    void findByEmailShouldReturnEmptyOptionalIfNotFound() {
        String email = "someEmail";
        Response response = mock(Response.class);

        when(client.findByUsername(email))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(404);

        Optional<LegacyUser> result = restUserService.findByEmail(email);
        assertTrue(result.isPresent());
    }

    @Test
    void shouldFindByUsername() {
        String username = "someUsername";
        LegacyUser expectedResult = new LegacyUser();
        Response response = mock(Response.class);

        when(client.findByUsername(username))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(200);
        when(response.readEntity(LegacyUser.class))
                .thenReturn(expectedResult);

        Optional<LegacyUser> result = restUserService.findByUsername(username);
        assertTrue(result.isPresent());
        assertEquals(expectedResult, result.get());
    }

    @Test
    void findByUsernameShouldReturnEmptyOptionalIfNotFound() {
        String username = "someUsername";
        Response response = mock(Response.class);

        when(client.findByUsername(username))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(404);

        Optional<LegacyUser> result = restUserService.findByUsername(username);
        assertTrue(!result.isPresent());
    }

    @Test
    void isPasswordValidShouldReturnTrueForValidPassword() {
        String username = "someUsername";
        String somePassword = "somePassword";
        Response response = mock(Response.class);

        when(client.validatePassword(username, new UserPasswordDto(somePassword)))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(200);

        boolean result = restUserService.isPasswordValid(username, somePassword);
        assertTrue(result);
    }

    @Test
    void isPasswordValidShouldReturnFalseForInvalidPassword() {
        String username = "someUsername";
        String somePassword = "somePassword";
        Response response = mock(Response.class);

        when(client.validatePassword(username, new UserPasswordDto(somePassword)))
                .thenReturn(response);
        when(response.getStatus())
                .thenReturn(403);

        boolean result = restUserService.isPasswordValid(username, somePassword);
        assertFalse(result);
    }
}
