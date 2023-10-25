package co.broadside.ipcheckservice.util;

import java.net.InetAddress;

import org.jboss.logging.Logger;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;

/**
 * This utility class checks an IP to be present in the range of IP address passed.
 * @author bhavyag
 */
public class IpRangeCheckUtil {
	
	private static final Logger LOG = Logger.getLogger(IpRangeCheckUtil.class);

	private IpRangeCheckUtil() {
	}
	
	/**
	 * This method checks IP against a range of IP passed.
	 * @param validIpList : IP range against which the IP is to be checked
	 * @param ipToBeValidated : IP which needs to be validated agains the range.
	 * @return true if IP is within range else false. 
	 */
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
			}else if(ip.contains(":")) {
				IPAddress loopback = new IPAddressString(ip).getAddress();
				InetAddress inetAddress = loopback.toInetAddress();
				String derivedIp=inetAddress.toString().split("/")[1];
				LOG.debug("ipToBeValidated:["+ipToBeValidated+"]||derivedIp:["+derivedIp+"]||ipList:["+ip+"]");
				if(ipToBeValidated.equals(derivedIp)) {
					isValid=true;
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
