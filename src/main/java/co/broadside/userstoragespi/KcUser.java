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
    
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public String getPassword() {
		//TODO : encryption logic?
		return password;
	}
	public void setPassword(String password) {
		//TODO : encryption logic?
		this.password = password;
	}
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public Long getCreated() {
		return created;
	}
	public void setCreated(Long created) {
		this.created = created;
	}
	public String getGeoLocation() {
		return geoLocation;
	}
	public void setGeoLocation(String geoLocation) {
		this.geoLocation = geoLocation;
	}
	public String getIpWhiteList() {
		return ipWhiteList;
	}
	public void setIpWhiteList(String ipWhiteList) {
		this.ipWhiteList = ipWhiteList;
	}
	public String getMobileNo() {
		return mobileNo;
	}
	public void setMobileNo(String mobileNo) {
		this.mobileNo = mobileNo;
	}
	@Override
	public String toString() {
		return "KcUser [id=" + id + ", username=" + username + ", email=" + email + ", firstName=" + firstName
				+ ", lastName=" + lastName + ", password=" + password + ", enabled=" + enabled + ", created=" + created
				+ ", geoLocation=" + geoLocation + ", ipWhiteList=" + ipWhiteList + ", mobileNo=" + mobileNo + "]";
	}
	
}
