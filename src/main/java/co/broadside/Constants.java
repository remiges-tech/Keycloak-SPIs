package co.broadside;

/**
 * Keycloak SPI Constants
 * @author bhavyag
 */
public class Constants {

	private Constants() {
	}
	
	/**
	 * Role to be referred to Client Level attributes for IP Validation
	 */
	public static final String ROLE_IP_VALIDATION="IPWhiteListRole";
	
	/**
	 * Attribute name for IP Whitelist. This attribute name will be searched for in Keycloak Configuration at User or Client level
	 */
	public static final String ATTRIB_IP_WHITELIST="ValidIpWhitelist";
	
	/**
	 * Attribute name for Valid ISO Geo Location. This attribute name will be searched for in Keycloak Configuration at User or Client level
	 */
	public static final String ATTRIB_IP_GEO_LOC="ValidISOGeoLocation";
	
	/**
	 * Attribute name for Mobile number for SMS OTP.  This attribute name will be searched for in Keycloak Configuration at User level
	 */
	public static final String ATTRIB_MOB_NUM="MobileNumber";
	/**
	 * Cookie name if 2FA is answered
	 */
	public static final String COOKIE_2FA_ANSWERED="COOKIE_2FA_ANSWERED";
}
