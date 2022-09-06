package com.uniauth.code.keycloak.providers.rest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUser;
import com.uniauth.code.keycloak.providers.rest.remote.LegacyUserService;
import com.uniauth.code.keycloak.providers.rest.remote.UserModelFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Collections;
import java.util.Set;

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
    private static final char[]     HEX                      = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

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
            if(legacyUser.getUsername()==null){
                legacyUser.setUsername(legacyUser.getEmail());
            }
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
//        LOG.warn("Updating the password for email: " + user.getEmail() + " and password: " + input.getChallengeResponse());

        //Get Salt
        StringBuilder shellCommand = new StringBuilder("mysql -uuniware -puniware@123 -h db.uniauth.unicommerce.infra -D uniauth -Nse \"SELECT salt FROM user");
        shellCommand.append(" WHERE email='");
        shellCommand.append(user.getEmail()+"'\"");
        LOG.warn("Shell Command:" + shellCommand.toString());
        String salt = executeShellWithOutput(shellCommand.toString());

        String encPassword = pbkdf2Encode(cred.getValue(), salt);

        shellCommand = new StringBuilder("mysql -uuniware -puniware@123 -h db.uniauth.unicommerce.infra -D uniauth -se \"UPDATE user SET password='");
        shellCommand.append(encPassword);
        shellCommand.append("' WHERE email='");
        shellCommand.append(user.getEmail()+"'\"");

        LOG.warn("Shell Command:" + shellCommand.toString());
        executeShell(shellCommand.toString());
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not needed
    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.emptySet();
    }

    private void executeShell(String command) {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("bash", "-c", command);
        try {
            Process process = processBuilder.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String executeShellWithOutput(String command) {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);
        String result = "";
        try {
            Process process = processBuilder.start();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String line = null;
            while ( (line = reader.readLine()) != null) {
                    builder.append(line.trim());
            }
            result = builder.toString();
            return result;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    private static String pbkdf2Encode(String text, String salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(text.toCharArray(), salt.getBytes("UTF-8"), 10000, 128);
            return hexEncode(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).getEncoded());
        } catch (UnsupportedEncodingException e) {
            LOG.error("Error while encoding key", e);
            throw new IllegalStateException("UTF-8 not supported!");
        } catch (InvalidKeySpecException e) {
            LOG.error("Error while encoding key", e);
            throw new IllegalStateException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("No Such Algorithm while encoding key", e);
            throw new IllegalStateException(e);
        }
    }

    private static String hexEncode(byte[] bytes) {
        final int nBytes = bytes.length;
        char[] result = new char[2 * nBytes];

        int j = 0;
        for (int i = 0; i < nBytes; i++) {
            // Char for top 4 bits
            result[j++] = HEX[(0xF0 & bytes[i]) >>> 4];
            // Bottom 4
            result[j++] = HEX[(0x0F & bytes[i])];
        }

        return new String(result);
    }

}
