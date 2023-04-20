# keycloak-spis

This is an implementation of a Service Provider Interface (SPI) for Keycloak.<br>
Standard Keycloak configuration does not allow for SMS based OTP or IP level validation.<br>
This SPI manages to add this feature to Keycloak in a configurable manner.

## Use-Case
1. IP based validation (can be set at Client Level & User Level): 
    - Whitelist of Range of IP or List of IP is defined in the attributes against which the user IP is validated. 
    - GeoIP Validation : A User can be based on a single Geo Located Country(for e.g. IN). 

2. SMS Based OTP
  We want to enables SMS based OTP to optionally be a part of the Authentication flow. An SPI is written for this purpose.

## Dependencies
Certain external Libraries are to be included on KEYCOAK_HOME/providers directory. Following are those list:
1. ipaddress-5.3.3.jar : This is for IP Address range validation
2. geoip2-4.0.1.jar : For GeoIP Validation
3. maxmind-db-3.0.0.jar : For Geo IP Validation
4. GeoLite2-Country.mmdb : GeoIP country Database


## Building the Module from scratch

This is a Java maven project, so just execute `mvn clean install`.
This builds a `keycloak-broadside-spi-1.0.1.jar` in the target directory.


## Installing the module (scriptable)

It is not automatic, because you have to provide the scripts to automate the installation.

You can automatically load the provider in keycloak by putting the `keycloak-broadside-spi-1.0.1.jar` to the directory `${KEYCLOAK_HOME}/providers/`
Also place all the dependencies from above steps inlcuding JARs and geoip database on the same path


## Configuring and Using the SPI [If using Keycloak's user management function]
If you want to use Custom User table then [go here](#Chapter1)

The new SPI fits in the registration flow of keycloaks registration.

**[A] IP/IP RANGE VALIDATION : Whitelist of Range of IP or List of IP is defined in the attributes against which the user IP is validated.**

Following properties are to be set in Keycloak for this to work: 
  1. __Authentication Flow level__  (Enable/Disable IP Validation):
     1. Login to Keycloak Admin Portal
     2. Select relevant Realm
     3. Under "Configure" section on Left Sidebar, select "Authentication" 
     4. Select the relevant flow like 'browerWithSMS_OTP' or 'browser' 
     5. If step "IP Validator" is present  
          - click on settings besides it and enable/disable it 
     6. If step "IP Validator" is not present, 
          - click on "Add Step" at relevant position in the flow, 
          - Search for "IP Validator" and Click Add. 
          - Go to setting besides "IP Validator" and add any alias and Enable/Disable 'IP Validation'
          
  2. __At Client Level__  (Valid IP Range): 
     1. Login to Keycloak Admin portal.
     2. Select relevant Realm 
     3. Under "Manage" section on the Left sidebar, select "Client"
     4. Click on Client where you want to set the attribute. For e.g. for Browser flow, select "account-console"
     5. Click on Roles
     6. If role "IPWhiteListRole" is not present, then add it, else select the role.
     7. In attributes for the Role, add the attribute "ValidIpWhitelist" along with value as the whitelist.
     8. Click on Save.
     
  3. __At User Level__  (Valid IP Range): 
     1. Login to Keycloak Admin Portal 
     2. Select relevant Realm 
     3. Under "Manage" section on the Left sidebar, select "Users" 
     4. Click on the user where you want to add IP Validation
     5. Click on "Attributes"
     6. Add the attribute key as "ValidIpWhitelist" and Value as IP range CSV e.g. "127.0.0.1-127.0.0.3,127.0.0.5,192.168.0.220-192.168.0.224" [without quotes]
     7. Click on Save and test.
     
     
 **[B] GEO LOCATION VALIDATION : IP is validated against Geo Location of IP using maxmind's geoIP2Lite DB**
 
 Following properties are to be set in Keycloak for this to work:
 1. __Authentication Flow level__  (Enable/Disable Geo Location based IP Validation): 
    1. Login to Keycloak Admin Portal
   	2. Select relevant Realm
    3. Under "Configure" section on Left Sidebar, select "Authentication"
    4. Select the relevant flow like 'browerWithSMS_OTP' or 'browser'
    5. If step "IP Validator" is present, 
        - click on settings besides it and enable/disable it
    6. If step "IP Validator" is not present, 
        - click on "Add Step" at relevant position in the flow,
        - Search for "IP Validator" and Click Add.
        - Go to setting besides "IP Validator" and add any alias and Enable/Disable 'Geo IP Validation'.
        
  2. __At Client Level__  (Valid Geo Location):
     1. Login to Keycloak Admin portal.
     2. Select relevant Realm 
     3. Under "Manage" section on the Left sidebar, select "Client"
     4. Click on Client where you want to set the attribute. For e.g. for Browser flow, select "account-console"
     5. Click on Roles
     6. If role "ValidISOGeoLocation" is not present, then add it, else select the role.
     7. In attributes for the Role, add the attribute "ValidISOGeoLocation" along with valid ISO Geo location e.g. "IN".
     8. Click on Save.
     
 2. __At User Level__  (Valid Geo Location):
     1. Login to Keycloak Admin Portal
     2. Select relevant Realm
     3. Under "Manage" section on the Left sidebar, select "Users" 
     4. Click on the user where you want to add IP Validation
     5. Click on "Attributes"
     6. Add the attribute key as "ValidISOGeoLocation" and Value as ISO Country code e.g. "IN" [without quotes]
     7. Click on Save and test.

<div id="Chapter1"/>

## Configuring and Using the SPI [If you want to use your own Custom table]
Custom table will be created here called __'KCUSER'__ .

The table has following fields:
  * id
  * username
  * email
  * firstname
  * lastname
  * password
  * created
  * geolocation : e.g. "IN" [without quotes]
  * ipwhitelist : e.g. "127.0.0.1-127.0.0.3,127.0.0.5,192.168.0.220-192.168.0.224" [without quotes]
  * mobileno
  
Add details to this table in your database. It'll use the same schema details as keycloak. [Note:  In case you want to use different database, use DBUtil.java to read DB creds from keycloak.conf and create custom connection ]

Configure keyclaok to use our custom User Storage table
   1. Login to Keycloak Admin Portal
   2. Select the relevant Realm
   3. Click on 'User federation' on the left sidebar
   4. Click on 'Add kc-db-user-provider provider'
   5. Add a Console display name.

That's it.

Now Keycloak will use your KCUSER table for authentication.

Note that at this point, the password is stored in plain text in the  __KCUSER__  table and the same is passed for authentication.

In all cases, you would want to encrypt your password. Add your logic in method  __'validateCredentials'__  of  __'KcUserRepository.java'__