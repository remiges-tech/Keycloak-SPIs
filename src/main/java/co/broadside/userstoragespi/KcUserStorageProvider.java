package co.broadside.userstoragespi;

import java.util.Map;
import java.util.stream.Stream;

import javax.persistence.EntityManager;

import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

/**
 * This SPI extends Keycloak UserStorage to use our custom Users from KcUser database table.
 * @author bhavyag
 */
public class KcUserStorageProvider implements UserStorageProvider,
        UserLookupProvider, UserQueryProvider, CredentialInputUpdater, CredentialInputValidator,
        UserRegistrationProvider {

    private final KeycloakSession session;
    private final ComponentModel model;
    private final KcUserRepository repository;
    protected EntityManager entityManager;

    public KcUserStorageProvider(KeycloakSession session, ComponentModel model, KcUserRepository repository) {
        this.session = session;
        this.model = model;
        this.repository = repository;
        /*
         * "user-store" in line below is referred from "persistence.xml" in META-INF folder
         */
        entityManager = session.getProvider(JpaConnectionProvider.class, "user-store").getEntityManager();
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        UserCredentialModel cred = (UserCredentialModel) input;
        return repository.validateCredentials(entityManager, user.getUsername(), cred.getChallengeResponse());
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
            return false;
        }
        UserCredentialModel cred = (UserCredentialModel) input;
        return repository.updateCredentials(entityManager, user.getUsername(), cred.getChallengeResponse());
    }    

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String externalId = StorageId.externalId(id);
        return new KcUserAdapter(session, realm, model, repository.findUserById(entityManager,externalId));
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        KcUser user = repository.findUserByUsernameOrEmail(entityManager,username);
        if (user != null) {
            return new KcUserAdapter(session, realm, model, user);
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return getUserByUsername(realm, email);
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return repository.getUsersCount(entityManager);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search) {
        return repository.findUsers(entityManager,search).stream()
                .map(user -> new KcUserAdapter(session, realm, model, user));
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        return searchForUserStream(realm, search);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        return repository.getAllUsers(entityManager).stream()
                .map(user -> new KcUserAdapter(session, realm, model, user));
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        return null;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        return false;
    }
}