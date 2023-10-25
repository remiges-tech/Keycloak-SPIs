package co.broadside.ipcheckservice.util;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;


import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.Config.ConfigProvider;
import org.keycloak.Config.Scope;
import org.keycloak.Config.SystemPropertiesConfigProvider;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.record.Country;

/**
 * This Utility class will load GeoIP2 DB in cache and provides util class for
 * checking of IP against the GeoIP DB.
 * @author bhavyag
 */
public class GeoIp2Util {

	private static final Logger LOG = Logger.getLogger(GeoIp2Util.class);

	private DatabaseReader reader;
	private File database;
	private static GeoIp2Util geoIp2Util;// =new GeoIp2Util();

	/**
	 * Singleton class that returns instancce of GeoIp2Util
	 * @return GeoIp2Util instance
	 * @throws IOException : Throws exception if it is unable to open the GeoIP2 DB file
	 */
	public static GeoIp2Util getGeoIp2Util() throws IOException {
		if (geoIp2Util == null) {
			geoIp2Util = new GeoIp2Util();
		}
		return geoIp2Util;
	}

	/**
	 * Constructor to initialize and load GeoIP2 DB file in cache
	 * @throws IOException : Throws exception if it is unable to open the geoip2 database
	 */
	private GeoIp2Util() throws IOException {
		//Config.ConfigProvider.
		String geoIP2DB =System.getenv("KC_DIR")+"/providers/GeoLite2-Country.mmdb";
		LOG.info("Geo IP2 DB Path::" + geoIP2DB);
		database = new File(geoIP2DB);
		reader = new DatabaseReader.Builder(database).withCache(new CHMCache()).build();
		testGeoIp2();
		LOG.info("GEOIP2 initialized");
	}

	/**
	 * This class tests loaded GeoIP2 DB against an hard coded IP based in US.
	 */
	private void testGeoIp2() {
		InetAddress ipAddress;
		try {
			ipAddress = InetAddress.getByName("128.101.101.101");
			CountryResponse response = reader.country(ipAddress);

			Country country = response.getCountry();
			LOG.info("GeoIP2 test. Country code:" + country.getIsoCode());

		} catch (IOException | GeoIp2Exception e) {
			LOG.error("Error while testing GeoIP2");
			LOG.error(e);
		}

	}

	/**
	 * This method returns Geo Location of the IP address passed.
	 * @param ip : IP address whose Geo Location is to be found.
	 * @return Geo Location String
	 * @throws IOException : Throws exception if it is unable to open the geoip2 database
	 * @throws GeoIp2Exception : generic GeoIP2 error
	 */
	public String getIsoCountry(String ip) throws IOException, GeoIp2Exception {
		/*
		 * Handle case for local host
		 */
		if (ip.trim().equals("127.0.0.1") || ip.trim().equals("0:0:0:0:0:0:0:1")) {
			return "IN";
		}
		InetAddress ipAddress = InetAddress.getByName(ip);

		CountryResponse response = reader.country(ipAddress);

		Country country = response.getCountry();
		LOG.info(String.format("IpAddress<%s> belongs to country<%s>", ip, response.getCountry()));
		return country.getIsoCode();
	}
}
