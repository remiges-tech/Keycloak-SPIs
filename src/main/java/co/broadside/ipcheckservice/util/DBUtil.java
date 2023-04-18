package co.broadside.ipcheckservice.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

/**
 * This is a singleton DB Util class for reading some DB table if needed.
 * @author bhavyag
 */
public class DBUtil {

	private static final Logger LOG = Logger.getLogger(DBUtil.class);

	private static Connection connection;

	private DBUtil() {
	}

	/**
	 * Method returns a DB Connection
	 * @return java.sql.Connection object
	 * @throws ClassNotFoundException
	 * @throws SQLException
	 */
	public static Connection getConnection() throws ClassNotFoundException, SQLException {
		if (connection != null) {
			return connection;
		} else {
			try {
				Class.forName(ConfigProvider.getConfig().getConfigValue("kc.db-driver").getValue());
			} catch (ClassNotFoundException nfe) {
				LOG.error("Invalid JDBC driver: " + ConfigProvider.getConfig().getConfigValue("kc.db-driver").getValue()
						+ ". Please check if your driver if properly installed");
				throw nfe;
			}

			connection = DriverManager.getConnection(ConfigProvider.getConfig().getConfigValue("kc.db-url").getValue(),
					ConfigProvider.getConfig().getConfigValue("kc.db-username").getValue(),
					ConfigProvider.getConfig().getConfigValue("kc.db-password").getValue());

			LOG.info(
					"DB Connection Details: DB URL[" + ConfigProvider.getConfig().getConfigValue("kc.db-url").getValue()
							+ "] DB Username[" + ConfigProvider.getConfig().getConfigValue("kc.db-username").getValue()
							+ "] DB Password[" + ConfigProvider.getConfig().getConfigValue("kc.db-password").getValue()
							+ "] DB Schema[" + connection.getSchema() + "]");
			return connection;
		}
	}
}
