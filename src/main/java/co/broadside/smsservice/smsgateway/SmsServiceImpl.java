package co.broadside.smsservice.smsgateway;

import java.util.Map;

import org.jboss.logging.Logger;

/**
 * Sms Service Implementation for sending of SMS
 */
public class SmsServiceImpl implements ISmsService {

	//private static final SnsClient sns = SnsClient.create();

	private static final Logger LOG = Logger.getLogger(SmsServiceImpl.class);
	
	private final String senderId;

	SmsServiceImpl(Map<String, String> config) {
		senderId = config.get("senderId");		
	}

	@Override
	public void send(String phoneNumber, String message) {
		/*
		 * Actual code to send SMS is here.
		 */
		LOG.info("SMS SenderID:"+senderId);
	}

}