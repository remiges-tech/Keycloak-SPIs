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

import co.broadside.Constants;
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

	public static final String PROVIDER_ID = "client-secret-IP";

	private static final Logger LOG = Logger.getLogger(ClientIPValidator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		
		UserModel user = context.getUser();
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();		
		
		/*
		 * Find IP address with and without Proxy
		 */
		String ipWithoutProxy = context.getHttpRequest().getRemoteAddress();
		String ipWithProxy = context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
		
		/*
		 * Check if IP whitelist Validation is required.
		 */
		if (Boolean.parseBoolean(config.getConfig().getOrDefault("IP Validation", "true"))) {
			if(!ipWhitelistCheck(context, user, config, ipWithoutProxy, ipWithProxy)) {
				return;
			}
		}else {
			LOG.info("Not checking IP whitelist as it is disabled in Authentication flow");
		}
		
		
		/*
		 * Check if GEO IP validation is to be performed
		 */
		if(Boolean.parseBoolean(config.getConfig().getOrDefault("Geo IP Validation", "true"))) {		
			if(!geoIpCheck(context, user, config, ipWithoutProxy, ipWithProxy)) {
				return;
			}
		}else {
			LOG.info("Not checking GeoIP as it is disabled in Authentication flow");
		}
		
		context.success();
	}



	private boolean geoIpCheck(AuthenticationFlowContext context, UserModel user, AuthenticatorConfigModel config,String ipWithoutProxy, String ipWithProxy) {
		
			String countryIsoWithProxy="";
			String countryIsoWithoutProxy="";
			/*
			 * 1. Find Geo Location of the IP
			 */
			try {
				if(ipWithProxy!=null) {
					countryIsoWithProxy=GeoIp2Util.getGeoIp2Util().getIsoCountry(ipWithProxy);
				}
				if(ipWithoutProxy!=null) {
					countryIsoWithoutProxy=GeoIp2Util.getGeoIp2Util().getIsoCountry(ipWithoutProxy);
				}				
			} catch (IOException|GeoIp2Exception e ) {
				LOG.error("Exception while reading GeoIP list:"+e.getLocalizedMessage());
				LOG.error(e);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError(String.format("GeoIP Database Error for your IP <%s>/<%s>",ipWithoutProxy,ipWithProxy)).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return false;
			}
			/*
			 * 2. Get allowed Geo location for user from config
			 */
			String allowedGeoLocation="";
			String allowedCountry = user.getFirstAttribute(Constants.ATTRIB_IP_GEO_LOC);
			
			if(allowedCountry==null || allowedCountry.isBlank()) {
				LOG.info("User level Geo Location is not set. Checking Client level Geo Location");
				String clientLevelGeoLocation="";
				try {
					clientLevelGeoLocation=getClientLevelAttribute(context,Constants.ROLE_IP_VALIDATION,Constants.ATTRIB_IP_GEO_LOC);
				}catch (Exception e) {
					LOG.error("Exception while reading client level Geo Location : "+e.getLocalizedMessage());
				}
				
				if(clientLevelGeoLocation==null || clientLevelGeoLocation.isBlank()) {
					String errorString = String.format(
							"'ValidISOGeoLocation' attribute for the user <%s> is blank or not present. Please set it.",
							user.getUsername());
					LOG.error(errorString);

					context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
							context.form().setError(errorString).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
					return false;
				}else {
					allowedGeoLocation=clientLevelGeoLocation;
				}
				
			}else {
				allowedGeoLocation=allowedCountry;
			}
			LOG.warn(String.format("CountryofIP<%s>/<%s>|| allowedCountry<%s>",countryIsoWithoutProxy,countryIsoWithProxy,allowedGeoLocation));				
			
			/*
			 * 3. Validate Geo location of IP against allowed Geo Location
			 */
			if(allowedGeoLocation.equals(countryIsoWithoutProxy)||allowedGeoLocation.equals(countryIsoWithProxy)) {
				LOG.info("GeoIP2 validation success");
				context.success();
				return true;
			}else {
				String err=String.format("Your IP Address <%s>/<%s> belongs to <%s>/<%s> is not part of whitelisted Geo Location<%s> for you, therefore access is denied",
						ipWithoutProxy, ipWithProxy, countryIsoWithProxy, countryIsoWithoutProxy, allowedGeoLocation);
				LOG.error(err);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form()
						.setError(err)
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return false;
			}					
		
	}


	/**
	 * Method to fetch Client level Attribute from Role passed.
	 * @param context : AuthenticationFlowContext of Keycloak
	 * @param role : Role which needs to be fetched
	 * @param attribute : Attribute that needs to be fetched from the role passed
	 * @return : Attribute String of Role at Client level
	 */
	private String getClientLevelAttribute(AuthenticationFlowContext context, String role, String attribute) {
		return context.getSession().getContext().getClient().getRole(role).getAttributes().get(attribute).get(0);
	}

	/**
	 * 
	 * @param context
	 * @param user
	 * @param config
	 * @param ipWithoutProxy
	 * @param ipWithProxy
	 * @return
	 */
	private boolean ipWhitelistCheck(AuthenticationFlowContext context, UserModel user, AuthenticatorConfigModel config,
			String ipWithoutProxy, String ipWithProxy) {
		/*
		 * 1. Get IP against white list
		 */
		String ipWhiteList="";
		String userLevelIPWhitelist="";
		userLevelIPWhitelist = user.getFirstAttribute(Constants.ATTRIB_IP_WHITELIST);
		if (userLevelIPWhitelist==null || userLevelIPWhitelist.isBlank()) {
			/*
			 * If User level whitelist is not set, then we need to check Client level whitelist
			 */
			LOG.info("User level IP whitelist is not set. Checking Client level whitelist");
			String clientLevelIPWhitelist = "";
			try {
				clientLevelIPWhitelist = getClientLevelAttribute(context,Constants.ROLE_IP_VALIDATION,Constants.ATTRIB_IP_WHITELIST);
			} catch (Exception e) {
				LOG.error("Exception while reading client level IP Whitelist : "+e.getLocalizedMessage());
			}
			
			if(clientLevelIPWhitelist==null || clientLevelIPWhitelist.isBlank()) {
				String errorString = String.format(
						"'ValidIpWhitelist' attribute for the user <%s> is blank or not present at Client level and User Level. Please set it. Or ask admin to disable IP Validation",
						user.getUsername());
				LOG.error(errorString);

				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError(errorString).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return false;
			}else {
				ipWhiteList=clientLevelIPWhitelist;
			}			
			
		}else {
			ipWhiteList=userLevelIPWhitelist;
		}
		// TODO: Change logging to debug
		LOG.info(String.format("IP Address <%s> or <%s> || whitelist <%s>", ipWithoutProxy, ipWithProxy, ipWhiteList));

		/*
		 * 2. Check IP against white list
		 */
		if (!(IpRangeCheckUtil.checkIP(ipWhiteList, ipWithoutProxy)
				|| IpRangeCheckUtil.checkIP(ipWhiteList, ipWithProxy))) {
			LOG.error(String.format("IP Address <%s> or <%s> is not part of whitelist, therefore access is denied",
					ipWithoutProxy, ipWithProxy));

			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError(String.format(
							"Your IP Address <%s> or <%s> is not part of whitelist, therefore access is denied",
							ipWithoutProxy, ipWithProxy))
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return false;
		} else {
			LOG.info("IP validation success");
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
