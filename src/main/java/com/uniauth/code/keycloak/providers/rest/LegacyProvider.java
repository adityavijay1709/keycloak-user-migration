package com.uniauth.code.keycloak.providers.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUser;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUserService;
import com.uniauth.code.keycloak.providers.rest.remote.UserModelFactory;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Provides legacy user migration functionality
 */
public class LegacyProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputUpdater,
        CredentialInputValidator {

    private static final Logger LOG = Logger.getLogger(LegacyProvider.class);
    private static final Set<String> supportedCredentialTypes = Collections.singleton(PasswordCredentialModel.TYPE);
    private final KeycloakSession   session;
    private final LegacyUserService legacyUserService;
    private final UserModelFactory  userModelFactory;
    private final ComponentModel    model;

    public LegacyProvider(KeycloakSession session, LegacyUserService legacyUserService,
                          UserModelFactory userModelFactory, ComponentModel model) {
        this.session = session;
        this.legacyUserService = legacyUserService;
        this.userModelFactory = userModelFactory;
        this.model = model;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        LOG.warnf("Getting user from external repository: %s", username);
        LegacyUser legacyUser = null;
        try {
            legacyUser = legacyUserService.findByUsername(username);
        } catch (JsonProcessingException e) {
            LOG.error("Error in fetching user from repository e {}",e);
        }
        if(legacyUser==null)
            return null;
        else{
            return userModelFactory.create(legacyUser, realm);
        }
    }


    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        LOG.warn("getUserByEmail with email: "+ email);
        LegacyUser legacyUser = null;
        try {
            legacyUser = legacyUserService.findByEmail(email);
        } catch (JsonProcessingException e) {
            LOG.error("Error in fetching user from repository e {}",e);
        }
        if(legacyUser==null)
            return null;
        else{
            return userModelFactory.create(legacyUser, realm);
        }
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput input) {
        LOG.warn("isValid called");
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        String userIdentifier = getUserIdentifier(userModel);
        LOG.info(session.userCredentialManager().getStoredCredentialsByTypeStream(realmModel,userModel,"password").map(credentialModel -> credentialModel.getType()+" : "+credentialModel.getCredentialData()).collect(Collectors.toList()));
        long localStorePasswordCount = session.userCredentialManager().getStoredCredentialsByTypeStream(realmModel,userModel,"password").count();
        LOG.warn("last called with localStorePasswordCount: " +localStorePasswordCount);
        if (localStorePasswordCount==0 && legacyUserService.isPasswordValid(userIdentifier, input.getChallengeResponse())) {
            LOG.warn("Password validated from Provider for user-email: "+userModel.getEmail());
            session.userCredentialManager().updateCredential(realmModel, userModel, input);
            return true;
        }

        return false;
    }

    private String getUserIdentifier(UserModel userModel) {
        String userIdConfig = model.getConfig().getFirst(ConfigurationProperties.USE_USER_ID_FOR_CREDENTIAL_VERIFICATION);
        boolean useUserId = Boolean.parseBoolean(userIdConfig);
        return useUserId ? userModel.getId() : userModel.getEmail();
    }

    @Override
    public boolean supportsCredentialType(String s) {
        return supportedCredentialTypes.contains(s);
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {

        LOG.warnf("getUserById from external repository: %s", id);

        throw new UnsupportedOperationException("User lookup by id not implemented");
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return false;
    }

    @Override
    public void close() {
        // Not needed
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel))
            return false;
        if (!input.getType().equals(CredentialModel.PASSWORD))
            return false;
        UserCredentialModel cred = (UserCredentialModel) input;
        LOG.warn("Updating the password for email: " + user.getEmail() + " and password: " + input.getChallengeResponse());
        legacyUserService.updatePassword(user.getEmail(), cred.getValue());
        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not needed
    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.emptySet();
    }

}
