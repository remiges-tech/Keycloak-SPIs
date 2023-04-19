package co.broadside.smsservice.smsgateway;

import java.util.Map;

import org.jboss.logging.Logger;

/**
 * SMS Service factory
 */
public class SmsServiceFactory {

	private static final Logger LOG = Logger.getLogger(SmsServiceFactory.class);

	private SmsServiceFactory() {		
	}
	
	public static ISmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (phoneNumber, message) ->
				LOG.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		} else {
			//TODO: Actual SMS service call
			return new SmsServiceImpl(config);
		}
	}
}
