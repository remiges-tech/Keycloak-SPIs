package co.broadside.ipcheckservice;

import java.io.IOException;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.maxmind.geoip2.exception.GeoIp2Exception;

import co.broadside.ipcheckservice.util.AttributesReader;
import co.broadside.ipcheckservice.util.GeoIp2Util;
import co.broadside.ipcheckservice.util.IpRangeCheckUtil;

/**
 * This SPI for Keycloak checks for IP based validation for a user.
 * 
 * [A] IP/IP RANGE VALIDATION : Whitelist of Range of IP or List of IP is defined in the attributes against which the user IP is validated.
 *     ~~~~~~~~~~~~~~~~~~~~~~~
 * Following properties are to be set in Keycloak for this to work:
 * 	1. Authentication Flow level [Enable/Disable IP Validation]: 
 * 		 a. Login to Keycloak Admin Portal
 *  	 b. Select relevant Realm
 *   	 c. Under "Configure" section on Left Sidebar, select "Authentication"
 *   	 d. Select the relevant flow like 'browerWithSMS_OTP' or 'browser'
 *   	 e. i. If step "IP Validator" is present, click on settings besides it and enable/disable it
 *       	ii. If step "IP Validator" is not present, 
 *          	 click on "Add Step" at relevant position in the flow,
 *          	 Search for "IP Validator" and Click Add.
 *          	 Go to setting besides "IP Validator" and add any alias and Enable/Disable 'IP Validation'
 * 	2. At User Level [Valid IP Range]:
 *    	a. Login to Keycloak Admin Portal
 *    	b. Select relevant Realm
 *    	c. Under "Manage" section on the Left sidebar, select "Users" 
 *    	d. Click on the user where you want to add IP Validation
 *    	e. Click on "Attributes"
 *    	f. Add the attribute key as "ValidIpWhitelist" and Value as IP range CSV e.g. "127.0.0.1-127.0.0.3,127.0.0.5,192.168.0.220-192.168.0.224" [without quotes]
 *    	g. Click on Save and test
 *    
 * [B] GEO LOCATION VALIDATION : IP is validated against Geo Location of IP using maxmind's geoIP2Lite DB
 *    ~~~~~~~~~~~~~~~~~~~~~~~~
 * Following properties are to be set in Keycloak for this to work:
 *  1. Authentication Flow level [Enable/Disable Geo Location based IP Validation]: 
 * 		 a. Login to Keycloak Admin Portal
 *  	 b. Select relevant Realm
 *   	 c. Under "Configure" section on Left Sidebar, select "Authentication"
 *   	 d. Select the relevant flow like 'browerWithSMS_OTP' or 'browser'
 *   	 e. i. If step "IP Validator" is present, click on settings besides it and enable/disable it
 *       	ii. If step "IP Validator" is not present, 
 *          	 click on "Add Step" at relevant position in the flow,
 *          	 Search for "IP Validator" and Click Add.
 *          	 Go to setting besides "IP Validator" and add any alias and Enable/Disable 'Geo IP Validation'
 *  2. At User Level [Valid Geo Location]:
 *    	a. Login to Keycloak Admin Portal
 *    	b. Select relevant Realm
 *    	c. Under "Manage" section on the Left sidebar, select "Users" 
 *    	d. Click on the user where you want to add IP Validation
 *    	e. Click on "Attributes"
 *    	f. Add the attribute key as "ValidISOGeoLocation" and Value as ISO Country code e.g. "IN" [without quotes]
 *    	g. Click on Save and test
 * @author bhavyag
 *
 */
public class ClientIPValidator implements Authenticator {
	
	private static final Logger LOG = Logger.getLogger(ClientIPValidator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		
		/*
		 * Find IP address with and without Proxy
		 */
		String reqIpAddress=context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
		if(reqIpAddress==null|| reqIpAddress.isBlank()) {
			reqIpAddress=context.getHttpRequest().getRemoteAddress();
		}
		/*
		 * Check if IP whitelist Validation is required.
		 */
		if (Boolean.parseBoolean(config.getConfig().getOrDefault("IP Validation", "true"))) {
			if (!ipWhitelistCheck(context, reqIpAddress)) {
				return;
			}
		} else {
			LOG.info("Not checking IP whitelist as it is disabled in Authentication flow");
		}
		/*
		 * Check if GEO IP validation is to be performed
		 */
		if (Boolean.parseBoolean(config.getConfig().getOrDefault("Geo IP Validation", "true"))) {
			if (!geoIpCheck(context, reqIpAddress)) {
				return;
			}
		} else {
			LOG.info("Not checking GeoIP as it is disabled in Authentication flow");
		}
		context.success();
	}

	/**
	 * Method performs Geo Location Check
	 * @param context
	 * @param user
	 * @param ipWithoutProxy
	 * @param ipWithProxy
	 * @param kcUser
	 * @return true if Geo location check passes. Else false
	 */
	private boolean geoIpCheck(AuthenticationFlowContext context, String reqIpAddress) {
		String countryIso = "";
		/*
		 * 1. Find Geo Location of the IP
		 */
		try {
			if (reqIpAddress != null) {
				countryIso = GeoIp2Util.getGeoIp2Util().getIsoCountry(reqIpAddress);
			}
			
		} catch (IOException | GeoIp2Exception e) {
			LOG.error("Exception while reading GeoIP list:" + e.getLocalizedMessage());
			LOG.error(e);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError(
							String.format("GeoIP Database Error for your IP <%s>", reqIpAddress))
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return false;
		}
		/*
		 * 2. Get allowed Geo location for user from config
		 */
		String allowedGeoLocation = AttributesReader.fetchGeoLocationFromConfig(context,LOG);
		
		LOG.warn(String.format("CountryofIP <%s> is <%s>|| allowedCountry <%s>", reqIpAddress, countryIso, allowedGeoLocation));

		/*
		 * 3. Validate Geo location of IP against allowed Geo Location
		 */
		if (allowedGeoLocation.isBlank()) {
			LOG.info("Geo Location for user <%s> is not set at User and Client level. Hence skipping Geo Location Check");
			return true;
		} else {
			if (allowedGeoLocation.equals(countryIso)) {
				LOG.debug("GeoIP2 validation success");
				context.success();
				return true;
			} else {
				String err = String.format(
						"Your IP Address <%s> belongs to <%s> is not part of whitelisted Geo Location<%s> for you, therefore access is denied",
						reqIpAddress, countryIso, allowedGeoLocation);
				LOG.error(err);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError(err).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return false;
			}
		}
	}

	/**
	 * Method performs IP Whitelist check
	 * @param context
	 * @param user
	 * @param config
	 * @param ipWithoutProxy
	 * @param ipWithProxy
	 * @return
	 */
	private boolean ipWhitelistCheck(AuthenticationFlowContext context, String reqIpAddress) {
		/*
		 * 1. Get IP against white list
		 */
		String ipWhiteList = AttributesReader.fetchIpWhitelistFromConfig(context, LOG);
		
		// TODO: Change logging to debug
		LOG.info(String.format("IP Address <%s> || whitelist <%s>", reqIpAddress, ipWhiteList));

		/*
		 * 2. Check IP against white list
		 */
		if (!ipWhiteList.isBlank()) {
			if (!(IpRangeCheckUtil.checkIP(ipWhiteList, reqIpAddress))) {
				LOG.error(String.format("IP Address <%s> is not part of whitelist, therefore access is denied",
						reqIpAddress));

				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError(String.format(
								"Your IP Address <%s> is not part of whitelist, therefore access is denied",
								reqIpAddress)).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return false;
			} else {
				LOG.info("IP validation success");
				return true;
			}
		} else {
			LOG.info("IP Whitlelist is not present. Skipping IP validation");
			return true;
		}
	}	
	
	
	
	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
