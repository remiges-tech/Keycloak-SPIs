package co.broadside.userstoragespi;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQuery;

/**
 * This class is the Keycloak custom User entity object
 * @author bhavyag
 */
@NamedQuery(name="getUserByUsername", query="select u from KcUser u where u.username = :username")
@NamedQuery(name="getUserByUserId", query="select u from KcUser u where u.id = :id")
@NamedQuery(name="getUserByEmail", query="select u from KcUser u where u.email = :email")
@NamedQuery(name="getUserCount", query="select count(u) from KcUser u")
@NamedQuery(name="getAllUsers", query="select u from KcUser u")
@NamedQuery(name="searchForUser", query="select u from KcUser u where " + "( lower(u.username) like :search or u.email like :search ) order by u.username")
@Entity
public class KcUser {
	@Id
    private String id;
	/**
	 * Username/Email ID or logon
	 */
    private String username;
    /**
     * Email ID of the User
     */
    private String email;
    /**
     * First Name of the User
     */
    private String firstName;
    /**
     * Last Name of the User
     */
    private String lastName;
    /**
     * Password of the user.
     */
    private String password;
    /**
     * Is the user enabled?
     */
    private boolean enabled;
    /**
     * User object create date
     */
    private Long created;
    /**
     * Geo Location allowed for the user
     */
    private String geoLocation;
    /**
     * IP whitelist. CSV of individual IP or IP range
     */
    private String ipWhiteList;
    /**
     * Mobile Number of the user as per E.123 format. e.g. +919966996699
     */
    private String mobileNo;
    /**
     * getter
     * @return ID
     */
	public String getId() {
		return id;
	}
	/**
	 * Setter
	 * @param id ID
	 */
	public void setId(String id) {
		this.id = id;
	}
	/**
	 * Getter 
	 * @return username
	 */
	public String getUsername() {
		return username;
	}
	/**
	 * Setter to set username
	 * @param username username
	 */
	public void setUsername(String username) {
		this.username = username;
	}
	/**
	 * Getter
	 * @return Email
	 */
	public String getEmail() {
		return email;
	}
	/**
	 * Setter
	 * @param email email address
	 */
	public void setEmail(String email) {
		this.email = email;
	}
	/**
	 * Getter
	 * @return First Name
	 */
	public String getFirstName() {
		return firstName;
	}
	/**
	 * Setter
	 * @param firstName First Name
	 */
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	/**
	 * Getter
	 * @return Last Name
	 */
	public String getLastName() {
		return lastName;
	}
	/**
	 * Setter
	 * @param lastName Last Name
	 */
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	/**
	 * Getter
	 * @return password Password
	 */
	public String getPassword() {
		//TODO : encryption logic?
		return password;
	}
	/**
	 * Setter
	 * @param password Password
	 */
	public void setPassword(String password) {
		//TODO : encryption logic?
		this.password = password;
	}
	/**
	 * Getter
	 * @return is Enabled?
	 */
	public boolean isEnabled() {
		return enabled;
	}
	/**
	 * Setter
	 * @param enabled isEnabled?
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	/**
	 * Getter
	 * @return created timestamp in long
	 */
	public Long getCreated() {
		return created;
	}
	/**
	 * Setter
	 * @param created created timestamp in long
	 */
	public void setCreated(Long created) {
		this.created = created;
	}
	/**
	 * Getter
	 * @return Geo Location
	 */
	public String getGeoLocation() {
		return geoLocation;
	}
	/**
	 * Setter
	 * @param geoLocation ISO Geo Location e.g. "IN"
	 */
	public void setGeoLocation(String geoLocation) {
		this.geoLocation = geoLocation;
	}
	/**
	 * Getter
	 * @return IP Whitelist
	 */
	public String getIpWhiteList() {
		return ipWhiteList;
	}
	/**
	 * Setter
	 * @param ipWhiteList IP Whitelist
	 */
	public void setIpWhiteList(String ipWhiteList) {
		this.ipWhiteList = ipWhiteList;
	}
	/**
	 * Getter
	 * @return Mobile No
	 */
	public String getMobileNo() {
		return mobileNo;
	}
	/**
	 * Setter
	 * @param mobileNo Mobile No
	 */
	public void setMobileNo(String mobileNo) {
		this.mobileNo = mobileNo;
	}
	@Override
	/**
	 * Returns String representation of the object
	 */
	public String toString() {
		return "KcUser [id=" + id + ", username=" + username + ", email=" + email + ", firstName=" + firstName
				+ ", lastName=" + lastName + ", password=" + password + ", enabled=" + enabled + ", created=" + created
				+ ", geoLocation=" + geoLocation + ", ipWhiteList=" + ipWhiteList + ", mobileNo=" + mobileNo + "]";
	}
	
}
