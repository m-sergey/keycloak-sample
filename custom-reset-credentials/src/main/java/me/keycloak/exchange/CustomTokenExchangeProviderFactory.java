package me.keycloak.exchange;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;


public class CustomTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    public static final String PROVIDER_ID = "custom-exchange-provider";

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new CustomTokenExchangeProvider();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
