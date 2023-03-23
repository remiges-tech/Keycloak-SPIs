package co.broadside.ipcheckservice.util;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.record.Country;

public class GeoIp2Util {

	private static final Logger LOG = Logger.getLogger(GeoIp2Util.class);
	
	private DatabaseReader reader;
	private File database;
	
	private static GeoIp2Util geoIp2Util=new GeoIp2Util();	
	
	public static GeoIp2Util getGeoIp2Util() {
		if(geoIp2Util==null) {
			geoIp2Util=new GeoIp2Util();
		}
		return geoIp2Util;
	}
	
	private GeoIp2Util() {		
		
		String geoIP2DB=ConfigProvider.getConfig().getConfigValue("kc.home.dir").getValue()+"/providers/GeoLite2-Country.mmdb";
		LOG.info("Geo IP2 DB Path::"+geoIP2DB);
		database = new File(geoIP2DB);
		try {
			reader = new DatabaseReader.Builder(database).withCache(new CHMCache()).build();
		} catch (IOException e) {
			LOG.error("Exception while reading Geolite2 DB:"+e.getLocalizedMessage());
			LOG.error(e);			
		}		
		testGeoIp2();
		LOG.info("GEOIP2 initialized");
		
	}
	
	private void testGeoIp2() {
		InetAddress ipAddress;
		try {
			ipAddress = InetAddress.getByName("128.101.101.101");
			CountryResponse response=reader.country(ipAddress);
			
			Country country = response.getCountry();
			LOG.info("GeoIP2 test. Country code:"+country.getIsoCode());
			
		} catch (IOException|GeoIp2Exception e) {
			LOG.error("Error while testing GeoIP2");
			LOG.error(e);
		}
		
		
	}
	
	public String getIsoCountry(String ip) throws IOException, GeoIp2Exception {
		
		/*
		 * Handle case for local host
		 */
		if(ip.trim().equals("127.0.0.1")) {
			return "IN";
		}
		InetAddress ipAddress = InetAddress.getByName(ip);
		
		CountryResponse response=reader.country(ipAddress);
		
		Country country = response.getCountry();
		LOG.info(String.format("IpAddress<%s> belongs to country<%s>",ip,response.getCountry()));
		return country.getIsoCode();
	}
}
