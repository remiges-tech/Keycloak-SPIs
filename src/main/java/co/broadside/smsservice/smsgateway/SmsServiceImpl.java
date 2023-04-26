package co.broadside.smsservice.smsgateway;

import java.util.Map;

import org.jboss.logging.Logger;

import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.SmsSubmissionResponse;
import com.vonage.client.sms.messages.TextMessage;

/**
 * Sms Service Implementation for sending of SMS
 */
public class SmsServiceImpl implements ISmsService {

	//private static final SnsClient sns = SnsClient.create();

	private static final Logger LOG = Logger.getLogger(SmsServiceImpl.class);
	
	private String senderId;	
	private String apiKey;
	private String apiSecret;
	private VonageClient client;

	SmsServiceImpl(Map<String, String> config) {
		this.senderId = config.get("senderId");	
		this.apiKey=config.get("vonnageApiKey");
		this.apiSecret=config.get("vonnageApiSecret");
		this.client = VonageClient.builder().apiKey(apiKey).apiSecret(apiSecret).build();
		//LOG.info(String.format("SMS Parameters: SenderID<%s>, apiKey<%s>, apiSecret<%s>",senderId,apiKey,apiSecret));
	}

	
	@Override
	public void send(String phoneNumber, String message) {
		/*
		 * Actual code to send SMS is here.
		 */
		//String apiKey="789a7e40";
		//String apiSecret="noZM7K42igIfF7iN";	
		
		if(apiKey==null || apiKey.isBlank()|| apiSecret==null || apiSecret.isBlank()) {
			LOG.error("SMS ERROR: API Key and API Secret for Vonage is not available in keycloak.conf. Add these to send SMS");
			return;
		}		
		
		TextMessage vonMessage = new TextMessage(senderId, "919969548552", "A text message sent using the Vonage SMS API. OTP:"+message);
		SmsSubmissionResponse response = client.getSmsClient().submitMessage(vonMessage);
		
		LOG.debug(String.format("SMS : from:<%s>, to:<%s>, msg:<%s>",vonMessage.getFrom(),vonMessage.getTo(),vonMessage.getMessageBody()));
		
		if (response.getMessages().get(0).getStatus() == MessageStatus.OK) {
			LOG.info("Message sent successfully.");
		} else {
			LOG.error("Message failed with error: " + response.getMessages().get(0).getErrorText());
		}
	}

}