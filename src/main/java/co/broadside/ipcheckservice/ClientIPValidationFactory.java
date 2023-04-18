package co.broadside.ipcheckservice;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Client IP Validation Factory which implements Keycloak Authentication Factory.
 * This is used for IP validation SPI
 * @author bhavyag
 */
public class ClientIPValidationFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "ip-validator";
	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "IP Validator";
	}

	@Override
	public String getHelpText() {
		return "Validates incoming IP Against whitelisted IP addresses";
	}

	@Override
	public String getReferenceCategory() {
		return "IPValidator";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty("IP Validation", "IP Validation", "If off, IP Validation will be skipped. Ensure you set 'ValidIpWhitelist' attrbiute for user", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty("Geo IP Validation", "Geo IP Validation", "If off, Geo IP Validation will be skipped. Ensure you set 'ValidISOGeoLocation' attribute for the User", ProviderConfigProperty.BOOLEAN_TYPE, true)
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new ClientIPValidator();
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}
}
