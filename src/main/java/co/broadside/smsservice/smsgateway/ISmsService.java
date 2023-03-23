package co.broadside.smsservice.smsgateway;

public interface ISmsService {
	void send(String phoneNumber, String message);

}
