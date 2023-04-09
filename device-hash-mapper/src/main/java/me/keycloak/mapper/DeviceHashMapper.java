package me.keycloak.mapper;

import me.keycloak.util.SimpleClientConnection;
import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class DeviceHashMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger log = Logger.getLogger(DeviceHashMapper.class);

    /*
     * The ID of the token mapper. Is public, because we need this id in our data-setup project to
     * configure the protocol mapper in keycloak.
     */
    public static final String PROVIDER_ID = "oidc-device-hash-mapper";

    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        // The builtin protocol mapper let the user define under which claim name (key)
        // the protocol mapper writes its value. To display this option in the generic dialog
        // in keycloak, execute the following method.
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        // The builtin protocol mapper let the user define for which tokens the protocol mapper
        // is executed (access token, id token, user info). To add the config options for the different types
        // to the dialog execute the following method. Note that the following method uses the interfaces
        // this token mapper implements to decide which options to add to the config. So if this token
        // mapper should never be available for some sort of options, e.g. like the id token, just don't
        // implement the corresponding interface.
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, DeviceHashMapper.class);
    }

    private static final String DISPLAY_CATEGORY = "Token mapper";
    private static final String DISPLAY_TYPE = "Device hash mapper";
    private static final String HELP_TEXT = "Add a device hash to token";
    private static final String SESSION_DEVICE_HASH_ATTR = "device-hash";

    private static final String ERROR_INCORRECT_DEVICE_HASH = "incorrect_device_hash";

    @Override
    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mappingModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            final ClientSessionContext clientSessionCtx) {

        var deviceHash = userSession.getNote(SESSION_DEVICE_HASH_ATTR);
        log.info("Session: " + userSession.getId() + ". deviceHash: " + deviceHash);
        var newDeviceHash = generateDeviceHash(keycloakSession.getContext());

        if (deviceHash == null && newDeviceHash != null) {
            // First call in Keycloak session
            userSession.setNote(SESSION_DEVICE_HASH_ATTR, newDeviceHash);
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, newDeviceHash);
            log.info("Session: " + userSession.getId() + ". New device hash: " + newDeviceHash);
        } else if (deviceHash != null && deviceHash.equals(newDeviceHash)) {
            // Renew token
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, newDeviceHash);
            log.info("Session: " + userSession.getId() + ". The same device hash: " + newDeviceHash);
        } else {
            // No! Throw Keycloak event and skip to insert claim to token

            // TODO Fix to fill event correctly !!!
            EventBuilder event = new EventBuilder(keycloakSession.getContext().getRealm(), keycloakSession, new SimpleClientConnection());
            event.event(EventType.REFRESH_TOKEN_ERROR);
            event.error(ERROR_INCORRECT_DEVICE_HASH);

            log.error("Session: " + userSession.getId() + ". SECURITY_RISK: " + deviceHash + " " + newDeviceHash);
        }
    }

    private String generateDeviceHash(KeycloakContext context) {
        String deviceHash = null;
        MessageDigest md = null;

        if( context == null
                || context.getRequestHeaders() == null
                || context.getRequestHeaders().getHeaderString("User-Agent") == null
                || context.getRequestHeaders().getHeaderString("User-Agent").isEmpty()) {
            return null;
        }

        String value = context.getRequestHeaders().getHeaderString("User-Agent");
        log.info("User-Agent: " + value);

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        md.update(value.getBytes());
        byte[] digest = md.digest();
        deviceHash = DatatypeConverter.printHexBinary(digest).toUpperCase();

        return deviceHash;
    }

    @Override
    public String getDisplayCategory() {
        return DISPLAY_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
