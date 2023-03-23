package co.broadside.ipcheckservice.util;

import org.jboss.logging.Logger;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;

public class IpRangeCheckUtil {
	
	private static final Logger LOG = Logger.getLogger(IpRangeCheckUtil.class);

	public static boolean checkIP(String validIpList, String ipToBeValidated) {
		boolean isValid=false;
		if(ipToBeValidated==null) {
			return isValid;
		}
		for(String ip:validIpList.split(",")) {
			if(ip.contains("-")) {
				try {
					if(IpRangeCheck(ip.split("-"), ipToBeValidated)) {
						isValid=true;
					}
				} catch (AddressStringException e) {
					LOG.error("Input IP ["+ipToBeValidated+"] is Invalid :: "+e.getLocalizedMessage());
				}
			}else if(ipToBeValidated.equals(ip)) {
				isValid=true;
			}
		}		
		return isValid;
	}
	
	private static boolean IpRangeCheck(String ipRange[], String input) throws AddressStringException {
		if(ipRange.length!=2) {
			LOG.error("Invalid Range defined");
			return false;
		}else {
			
			return checkIPIsInGivenRange(input, ipRange[0], ipRange[1]);
		}
	}
	
	private static boolean checkIPIsInGivenRange (String inputIP, String rangeStartIP, String rangeEndIP) throws AddressStringException {		
	    IPAddress startIPAddress = new IPAddressString(rangeStartIP).getAddress();	    
	    IPAddress endIPAddress = new IPAddressString(rangeEndIP).getAddress();
	    IPAddressSeqRange ipRange = startIPAddress.toSequentialRange(endIPAddress);
	    IPAddress inputIPAddress = new IPAddressString(inputIP).toAddress();
	    return ipRange.contains(inputIPAddress);
	}
}
