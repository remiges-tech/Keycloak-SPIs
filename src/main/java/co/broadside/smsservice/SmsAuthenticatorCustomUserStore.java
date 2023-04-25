package co.broadside.smsservice;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.persistence.EntityManager;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.ServerCookie;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
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
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;

/**
 * This SPI can be used to send SMS OTP for Login Authentication using Keycloak.
 * Note that this SPI refers to mobile no from Custom User table 'KCUSER'
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
public class SmsAuthenticatorCustomUserStore implements Authenticator{

	private static final String TPL_CODE = "login-sms.ftl";
	private static final Logger LOG = Logger.getLogger(SmsAuthenticatorCustomUserStore.class);

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
			//LOG.warn("Mobile no for user not found in DB table. Checking at Keycloak level");
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
		
		/**
		 * Check if 2FA cookie check is to be performed
		 */
		if(Boolean.parseBoolean(config.getConfig().get(Constants.ATTRIB_2FA_COOKIE))) {
			/**
			 * Check if 2FA was already done within last 7 days.
			 */
			if(hasCookie(context)) {
	            context.success();
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
			 * Send OTP
			 */
			sendOTP(context, config, session, user, mobileNumber, ttl, code);
			
		}catch(NumberFormatException e) {
			LOG.error(String.format("Unable to parse length<%s> or ttl<%s> for the Authentication Flow",config.getConfig().get("length"),config.getConfig().get("ttl")));
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("smsAuthSmsNotSent", e.getMessage())
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	private void sendOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config, KeycloakSession session,
			UserModel user, String mobileNumber, int ttl, String code) {		
		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));
			/*
			 * SMS OTP Send
			 */
			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
			/*
			 * Email OTP Send
			 */
			sendEmailWithCode(session, context.getRealm(), user, code);
			
			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", e.getMessage())
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}
	
	
	@Override
	public void action(AuthenticationFlowContext context) {
		
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("resend")) {
            //removeSessionOTP(context);
        	sendEmailWithCode(context.getSession(), context.getRealm(), context.getUser(), context.getAuthenticationSession().getAuthNote("code"));
        	LOG.info("Resending OTP");
            return;
        }
		
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
				/*
				 * OTP expired
				 */
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				/*
				 * OTP is valid
				 */
				//TODO change logging to debug
				LOG.info("OTP validation success for "+context.getUser().getEmail());
				context.success();
				setCookie(context);
				removeSessionOTP(context);
			}
		} else {
			// OTP is invalid
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

	private void removeSessionOTP(AuthenticationFlowContext context) {
		context.getAuthenticationSession().removeAuthNote("code");
		context.getAuthenticationSession().removeAuthNote("ttl");
	}

	
	private boolean hasCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(Constants.COOKIE_2FA_ANSWERED);
        boolean result = cookie != null;
        if (result) {
            LOG.info("Bypassing 2FA because cookie as set");
        }
        return result;
    }
	
	private void setCookie(AuthenticationFlowContext context) {
		if(!Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get(Constants.ATTRIB_2FA_COOKIE))) {
			return;
		}
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        
        int maxCookieAge = 0;
        if (config != null) {
            maxCookieAge = 60 * 60 * 24 * Integer.valueOf(config.getConfig().get("cookieMaxAge"));
        }
        //TODO : Encrypt cookie using keys and check encrypted cookie
        URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();
        addCookie(Constants.COOKIE_2FA_ANSWERED, "true",
                uri.getRawPath(),
                null, null,
                maxCookieAge,
                false, true);
    }
	
	private static void addCookie(String name, String value, String path, String domain, String comment, int maxAge, boolean secure, boolean httpOnly) {
        HttpResponse response= ResteasyProviderFactory.getInstance().getContextData(HttpResponse.class);
        StringBuffer cookieBuf = new StringBuffer();
        ServerCookie.appendCookieValue(cookieBuf, 1, name, value, path, domain, comment, maxAge, secure, httpOnly, null);
        String cookie = cookieBuf.toString();
        response.getOutputHeaders().add(HttpHeaders.SET_COOKIE, cookie);
    }
	
	private void sendEmailWithCode(KeycloakSession session,RealmModel realm, UserModel user, String code) {
        if (user.getEmail() == null) {
            LOG.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", user.getUsername());
        mailBodyAttributes.put("code", code);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            // Don't forget to add the welcome-email.ftl (html and text) template to your theme.
            emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException eex) {
            LOG.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
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
