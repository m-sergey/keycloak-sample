package me.keycloak.mapper;

import me.keycloak.model.Id;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class SystemsIdsMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-systems-ids-mapper";

    private static final Logger LOG = LoggerFactory.getLogger(SystemsIdsMapper.class);

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final String PREFIX = "ids.";

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
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, SystemsIdsMapper.class);

        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.MULTIVALUED);
        property.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
        property.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue("true");
        configProperties.add(property);
    }

    private Collection<Id> findAttribute(UserModel user) {
        var list = new ArrayList<Id>();

        for (Map.Entry<String, List<String>> attr : user.getAttributes().entrySet()) {
            if(attr.getKey().startsWith(PREFIX)){
               list.add(new Id(attr.getKey().substring(PREFIX.length()), attr.getValue().get(0)));
            }
        }
        return list;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        Collection<Id> attributeValue = findAttribute(user);
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Maps ids of external systems";
    }

    @Override
    public String getHelpText() {
        return "Maps ids of external systems";
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
