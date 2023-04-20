package co.broadside.userstoragespi;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

/**
 * Adapter over KCUser class. Extension to keycloak AbstractUserAdapter
 * @author bhavyag
 *
 */
public class KcUserAdapter extends AbstractUserAdapter {

    private final KcUser user;

    /**
     * Constructor required by Keycloak
     * @param session Keycloak Session
     * @param realm RealmModel
     * @param model ComponentModel
     * @param user KcUser
     */
    public KcUserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, KcUser user) {
        super(session, realm, model);
        this.storageId = new StorageId(storageProviderModel.getId(), user.getId());
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public String getFirstName() {
        return user.getFirstName();
    }

    @Override
    public String getLastName() {
        return user.getLastName();
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this);
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public Long getCreatedTimestamp() {
        return user.getCreated();
    }

    /**
     * Get Geo Location 
     * @return ISO Geo Location
     */
    public String getGeoLocation() {
    	return user.getGeoLocation();
    }
    
    /**
     * Get IP Whitelist
     * @return IP Whitelist
     */
    public String getIpWhiteList() {
    	return user.getIpWhiteList();
    }
    
    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL, getEmail());
        attributes.add(UserModel.FIRST_NAME, getFirstName());
        attributes.add(UserModel.LAST_NAME, getLastName());
        return attributes;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        if (name.equals(UserModel.USERNAME)) {
            return Stream.of(getUsername());
        }
        return Stream.empty();
    }

    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
		/*
		 * if (user.getRoles() != null) { return user.getRoles().stream().map(roleName
		 * -> new KcUserRoleModel(roleName, realm)).collect(Collectors.toSet()); }
		 */
        return Set.of();
    }
    
    @Override
    public void addRequiredAction(String action) {
    	super.addRequiredAction(action);
    }
    @Override
    public void addRequiredAction(RequiredAction action) {
    	super.addRequiredAction(action);
    }
}