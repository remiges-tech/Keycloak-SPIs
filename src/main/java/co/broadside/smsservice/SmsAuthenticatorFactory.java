package co.broadside.smsservice;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import co.broadside.Constants;

/**
 * Factory class for SMS OTP send SPI
 * @author bhavyag
 */
public class SmsAuthenticatorFactory implements AuthenticatorFactory{

	private static final String PROVIDER_ID = "sms-authenticator";

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "SMS Authentication";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS to the users mobile phone.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
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
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty("senderId", "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty("vonnageApiKey","Vonnage Api Key","API Key for sending sms via Vonnage",ProviderConfigProperty.PASSWORD,""),
			new ProviderConfigProperty("vonnageApiSecret","Vonnage Api Secret","API Secret for sending sms via Vonnage",ProviderConfigProperty.PASSWORD,""),
			new ProviderConfigProperty(Constants.ATTRIB_2FA_COOKIE, "Set Cookie For 2FA", "Set Cookie for 2FA which will disable 2FA for fixed days.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("cookieMaxAge", "Cookie Max Age in no of Days", "The number of days for which Cookie is valid for 2FA", ProviderConfigProperty.STRING_TYPE, "7"),
			new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true)
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new SmsAuthenticator();
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
