package co.broadside.userstoragespi;

import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;


public class KcUserStorageProviderFactory implements UserStorageProviderFactory<KcUserStorageProvider> {

	private static final String PROVIDER_ID = "kc-db-user-provider";
	
    @Override
    public KcUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        KcUserRepository repository = KcUserRepository.getKcUserRepository();
        return new KcUserStorageProvider(session, model, repository);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /*
     * If we want to set some custom parameter, we can code it in this method.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                /* Using custom JAR is not feasible as it'll be needed during startup time and not run time.
        	     * Further, passing password in plain text to a JAR(command line) for encryption does not seem like a good idea.
        	     * */
        		//.property("myCustomJAR", "My Custom JAR", "Custom JAR to be used for encryption of passwords. JAR name that is kept on '$KC_HOME/providers' path", ProviderConfigProperty.STRING_TYPE, "", null)
                //.property("useCustomJAR","Use Custom JAR for Passwords","Should Keycloak use Custom JAR for Encryption of passwords?", ProviderConfigProperty.BOOLEAN_TYPE,false, null)
        		
        		/* DB Schema Name as a property cannot be read at runtime like setting this property.
        		 * There are workarounds, but we possibly don't need this.
        		 * Workaround 1 : Override LocalContainerEntityManagerFactoryBean entityManagerFactory( DataSource dataSource) method to set our custom config.
        		 * Workaround 2 : use the DBUtil package to create custom DB connection and create SQL statements by appending the schema name for our usage.
        		 * */        		
        		//.property("dbSchemaName", "My DB Schema Name", "Schema name of DB where KCUser table exists", ProviderConfigProperty.STRING_TYPE, "public", null)
        		.build();
    }
}