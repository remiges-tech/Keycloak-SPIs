package co.broadside.smsservice;

import java.util.Locale;

import javax.persistence.EntityManager;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import co.broadside.Constants;
import co.broadside.smsservice.smsgateway.SmsServiceFactory;
import co.broadside.userstoragespi.KcUserRepository;

/**
 * This SPI can be used to send SMS OTP for Login Authentication using Keycloak.
 * To enable SMS OTP as a step in Authentication Workflow, 
 * 1. Login to Keycloak Admin Portal.
 * 2. Click on the relevant Realm on top Left corner.
 * 3. Click on "Authentication" in "configure" section on left sidebar.
 * 4. we'll create a copy of existing "Browser" workflow for our use.
 *  a. Click on "Browser" authentication flow
 *  b. on top right, there is a drop down named 'Action', select duplicate from it. This will create a duplicate browser authentication flow
 *  c. Name this new workflow to example 'browserWithSMSOtp'
 *  d. In 'browserWithSMSOtp forms' section, add a sub-section by clicking on '+' symbol besides the step and click on 'Add step'
 *  e. In the list search for 'SMS Authentication'.
 *  f. Add an alias to this setting, and set the parameters 
 *    'Code length' i.e. SMS OTP length
 *    'Time-to-live' i.e. TTL for which OTP is valid
 *    'SenderId' i.e. What should be the SenderId in the SMS OTP
 *    'Simulation mode' i.e. if on, it'll not actually send the OTP instead just print OTP in console
 *  g. Click on save 
 *  h. Now set the flow to be used for browser. So click on drop down 'Action' on top right and click on 'Bind Flow' and select 'Browser flow' and click on 'Save'
 * @author bhavyag
 *
 */
public class SmsAuthenticator implements Authenticator{

	private static final String TPL_CODE = "login-sms.ftl";
	private static final Logger LOG = Logger.getLogger(SmsAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		EntityManager em=context.getSession().getProvider(JpaConnectionProvider.class, "user-store").getEntityManager();
		KcUserRepository repository = KcUserRepository.getKcUserRepository();
		
		String mobileNumber="";
		/**
		 * Fetch mobile no from DB
		 */
		mobileNumber = repository.findUserByUsernameOrEmail(em, user.getUsername()).getMobileNo();
		
		/**
		 * Fetch mobile no from User attribute of Keycloak
		 */
		if(mobileNumber==null || mobileNumber.isBlank()) {
			LOG.warn("Mobile no for user not found in DB table. Checking at Keycloak level");
			mobileNumber = user.getFirstAttribute(Constants.ATTRIB_MOB_NUM);
			//TODO : Mobile No validation required?
			if(mobileNumber==null) {
				String errorString = String.format(
						"'%s' attribute for the user <%s>is blank or not present. Please set it.",
						Constants.ATTRIB_MOB_NUM,user.getUsername());
				LOG.error(errorString);

				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form()
						.setError(errorString)
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return;
			}
		}
		
		try {
			AuthenticationSessionModel authSession = context.getAuthenticationSession();
	
			/*
			 * If OTP was already generated, and is valid, then there is no need to re-generate the OTP.
			 */
			if(authSession.getAuthNote("code")!=null && Long.parseLong(authSession.getAuthNote("ttl")) > System.currentTimeMillis()) {
				context.attempted();
				return;
			}
			
			/*
			 * length: Length of OTP to be generated. This is currently defined in the Authentication flow. Can be read from config as well.
			 */
			int length = Integer.parseInt(config.getConfig().get("length"));
			/*
			 * ttl: Time to Live of OTP to be generated
			 */
			int ttl = Integer.parseInt(config.getConfig().get("ttl"));
		
			/*
			 * Generating OTP
			 */
			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			
			/*
			 * Set OTP in current device session
			 */
			authSession.setAuthNote("code", code);
			//TODO check TTL logic
			authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
			
			/*
			 * Send OTP SMS
			 */
			sendSms(context, config, session, user, mobileNumber, ttl, code);
			
		}catch(NumberFormatException e) {
			LOG.error(String.format("Unable to parse length<%s> or ttl<%s> for the Authentication Flow",config.getConfig().get("length"),config.getConfig().get("ttl")));
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("smsAuthSmsNotSent", e.getMessage())
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	private void sendSms(AuthenticationFlowContext context, AuthenticatorConfigModel config, KeycloakSession session,
			UserModel user, String mobileNumber, int ttl, String code) {
		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			/*
			 * Call SMS sending service
			 */
			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", e.getMessage())
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				//TODO change logging to debug
				LOG.info("OTP validation success for "+context.getUser().getEmail());
				context.success();
			}
		} else {
			// invalid
			LOG.error(String.format("OTP validation failed. Entered OTP <%s> does not match with required OTP ,%s>",enteredCode,code));
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("smsAuthCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		//return user.getFirstAttribute("mobile_number") != null;
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
