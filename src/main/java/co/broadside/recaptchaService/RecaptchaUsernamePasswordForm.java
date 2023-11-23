package co.broadside.recaptchaService;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.InputStream;
import java.util.*;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator{
	public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
	public static final String SITE_KEY = "site.key";
	public static final String SITE_SECRET = "secret";
	public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";
	private static final Logger logger = Logger.getLogger(RecaptchaUsernamePasswordForm.class);

	private String siteKey;

	@Override
	protected Response createLoginForm( LoginFormsProvider form ) {
		form.setAttribute("recaptchaRequired", true);
		form.setAttribute("recaptchaSiteKey", siteKey);
		return super.createLoginForm( form );
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
		if (logger.isInfoEnabled()) {
			logger.info(
					"validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
		}
		

		AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
		LoginFormsProvider form = context.form();
		String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
		//logger.info("1:::recaptchaSiteKey:["+siteKey+"]|domain:["+getRecaptchaDomain(captchaConfig)+"]");

		
		if (captchaConfig == null || captchaConfig.getConfig() == null
				|| captchaConfig.getConfig().get(SITE_KEY) == null
				|| captchaConfig.getConfig().get(SITE_SECRET) == null) {
			form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
			return;
		}
		siteKey = captchaConfig.getConfig().get(SITE_KEY);
		//logger.info("2:::recaptchaSiteKey:["+siteKey+"]|domain:["+getRecaptchaDomain(captchaConfig)+"]");

		form.setAttribute("recaptchaRequired", true);
		form.setAttribute("recaptchaSiteKey", siteKey);
		form.addScript("https://www." + getRecaptchaDomain(captchaConfig) + "/recaptcha/api.js?hl=" + userLanguageTag);
		
		//logger.info("3:::recaptchaSiteKey:["+siteKey+"]|domain:["+getRecaptchaDomain(captchaConfig)+"]");

		super.authenticate(context);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - start");
		}
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		List<FormMessage> errors = new ArrayList<>();
		boolean success = false;
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

		String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
		if (!Validation.isBlank(captcha)) {
			AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
			String secret = captchaConfig.getConfig().get(SITE_SECRET);

			success = validateRecaptcha(context, success, captcha, secret);
		}
		if (success) {
			super.action(context);
		} else {
			errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
			formData.remove(G_RECAPTCHA_RESPONSE);
//			 context.error(Errors.INVALID_REGISTRATION);
			// context.validationError(formData, errors);
			// context.excludeOtherErrors();
			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - end");
		}
	}

	private String getRecaptchaDomain(AuthenticatorConfigModel config) {
		Boolean useRecaptcha = Optional.ofNullable(config)
				.map(configModel -> configModel.getConfig())
				.map(cfg -> Boolean.valueOf(cfg.get(USE_RECAPTCHA_NET)))
				.orElse(false);
		if (useRecaptcha) {
			return "recaptcha.net";
		}

		return "google.com";
	}

	protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
		HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
		HttpPost post = new HttpPost("https://www." + getRecaptchaDomain(context.getAuthenticatorConfig()) + "/recaptcha/api/siteverify");
		List<NameValuePair> formparams = new LinkedList<>();
		formparams.add(new BasicNameValuePair("secret", secret));
		formparams.add(new BasicNameValuePair("response", captcha));
		formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
		try {
			UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
			post.setEntity(form);
			HttpResponse response = httpClient.execute(post);
			InputStream content = response.getEntity().getContent();
			try {
				Map json = JsonSerialization.readValue(content, Map.class);
				Object success_resp = json.get("success");
				Object score_resp=json.get("score");
				Object action_resp=json.get("action");
				String score_api="",action_api="";
				if(score_resp!=null) {
					score_api=score_resp.toString();
				}
				
				if(action_resp!=null) {
					action_api=action_resp.toString();
				}
				
				logger.info("RECAPTCHA: success["+success_resp.toString()+"]. score["+score_api+"]. action["+action_api+"]");
				
				if(score_api.length()>0) {
					float score=Float.parseFloat(score_api);
					if(score>0.7) { //TODO: Move this to properties
						success = Boolean.TRUE.equals(success_resp);
					}
				}else {
					success = Boolean.TRUE.equals(success_resp);
				}
				
			} finally {
				content.close();
			}
		} catch (Exception e) {
			ServicesLogger.LOGGER.recaptchaFailed(e);
		}
		return success;
	}

}
