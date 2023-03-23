package co.broadside;

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class playground implements AuthenticatorFactory {

	@Override
	public Authenticator create(KeycloakSession session) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(Scope config) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDisplayType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getReferenceCategory() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isConfigurable() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Requirement[] getRequirementChoices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isUserSetupAllowed() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getHelpText() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		// TODO Auto-generated method stub
		return null;
	}

}
