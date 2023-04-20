package co.broadside.smsservice.smsgateway;

/**
 * SMS send interface
 * @author bhavyag
 */
public interface ISmsService {
	/**
	 * Method to send SMS
	 * @param phoneNumber Phone Number
	 * @param message Message to send
	 */
	void send(String phoneNumber, String message);
}
