package com.uniauth.code.keycloak.providers.rest.remote;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.Optional;

/**
 * Interface to be implemented by Legacy user provider.
 */
public interface LegacyUserService {

    /**
     * Find user by email address.
     *
     * @param email email address to search user by.
     * @return Optional of legacy user.
     */
   LegacyUser findByEmail(String email) throws JsonProcessingException;

    /**
     * Find user by username.
     *
     * @param username username to search user by.
     * @return Optional of legacy user.
     */
   LegacyUser findByUsername(String username) throws JsonProcessingException;

    /**
     * Validate given password in legacy user provider.
     *
     * @param username username to validate password for.
     * @param password the password to validate.
     * @return true if password is valid.
     */
    boolean isPasswordValid(String username, String password);

    /**
     * Update password on external Store
     */
    boolean updatePassword(String email, String password);
}
