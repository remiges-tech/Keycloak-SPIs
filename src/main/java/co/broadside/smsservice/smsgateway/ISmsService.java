package co.broadside.smsservice.smsgateway;

/**
 * SMS send interface
 * @author bhavyag
 */
public interface ISmsService {
	void send(String phoneNumber, String message);
}
