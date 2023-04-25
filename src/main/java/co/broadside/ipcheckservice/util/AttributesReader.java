package co.broadside.ipcheckservice.util;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;

import co.broadside.Constants;

/**
 * Utility class to read Attributes from Keycloak's Client and User Structure
 * @author bhavyag
 */
public class AttributesReader {
	
	private AttributesReader() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Fetches Geo Location from config for the user trying to login
	 * @param context Keycloak's AuthenticationFlowContext
	 * @param logger Logging object to write logs
	 * @return String GeoLocation 
	 */
	public static String fetchGeoLocationFromConfig(AuthenticationFlowContext context, Logger logger) {
		UserModel user=context.getUser();
		String allowedGeoLocation = "";
		String allowedCountry = user.getFirstAttribute(Constants.ATTRIB_IP_GEO_LOC);

		if (allowedCountry == null || allowedCountry.isBlank()) {
			logger.info("User level Geo Location is not set. Checking Client level Geo Location");
			String clientLevelGeoLocation = "";
			try {
				clientLevelGeoLocation = getClientLevelAttribute(context, Constants.ROLE_IP_VALIDATION, Constants.ATTRIB_IP_GEO_LOC);
			} catch (Exception e) {
				logger.error("Exception while reading client level Geo Location : " + e.getLocalizedMessage());
			}

			if (clientLevelGeoLocation == null || clientLevelGeoLocation.isBlank()) {
				String errorString = String.format("Geo Location is not set at Client level for user <%s>", user.getUsername());
				logger.error(errorString);
			} else {
				allowedGeoLocation = clientLevelGeoLocation;
			}
		} else {
			allowedGeoLocation = allowedCountry;
		}
		return allowedGeoLocation;
	}
	
	/**
	 * Method to fetch Client level Attribute from Role passed.
	 * @param context : AuthenticationFlowContext of Keycloak
	 * @param role : Role which needs to be fetched
	 * @param attribute : Attribute that needs to be fetched from the role passed
	 * @return : Attribute String of Role at Client level
	 */
	private static String getClientLevelAttribute(AuthenticationFlowContext context, String role, String attribute) {
		return context.getSession().getContext().getClient().getRole(role).getAttributes().get(attribute).get(0);
	}
	
	/**
	 * Fetches IP Whitelist from config for the user trying to login
	 * @param context Keycloak's AuthenticationFlowContext
	 * @param logger Logging object to write logs
	 * @return String IPWhiteList
	 */
	public static String fetchIpWhitelistFromConfig(AuthenticationFlowContext context, Logger logger) {		
		UserModel user=context.getUser();
		String ipWhiteList = "";
		String userLevelIPWhitelist = "";
		userLevelIPWhitelist = user.getFirstAttribute(Constants.ATTRIB_IP_WHITELIST);
		if (userLevelIPWhitelist == null || userLevelIPWhitelist.isBlank()) {
			/*
			 * If User level whitelist is not set, then we need to check Client level whitelist
			 */
			logger.info("User level IP whitelist is not set. Checking Client level whitelist");
			String clientLevelIPWhitelist = "";
			try {
				clientLevelIPWhitelist = getClientLevelAttribute(context, Constants.ROLE_IP_VALIDATION,
						Constants.ATTRIB_IP_WHITELIST);
			} catch (Exception e) {
				logger.error("Exception while reading client level IP Whitelist : " + e.getLocalizedMessage());
			}

			if (clientLevelIPWhitelist == null || clientLevelIPWhitelist.isBlank()) {
				String errorString = String.format(
						"'ValidIpWhitelist' attribute for the user <%s> is blank or not present at Client level and User Level",
						user.getUsername());
				logger.error(errorString);
			} else {
				ipWhiteList = clientLevelIPWhitelist;
			}

		} else {
			ipWhiteList = userLevelIPWhitelist;
		}
		return ipWhiteList;
	}
}
