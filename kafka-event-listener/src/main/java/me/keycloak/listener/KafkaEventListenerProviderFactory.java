package me.keycloak.listener;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class KafkaEventListenerProviderFactory implements EventListenerProviderFactory {
    private static final Logger LOG = LoggerFactory.getLogger(KafkaEventListenerProviderFactory.class);
    private static final String PROVIDER_ID = "kafka-event-listener";
    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new KafkaEventListenerProvider(session);
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

//    @Override
//    public List<ProviderConfigProperty> getConfigMetadata() {
//        return EventListenerProviderFactory.super.getConfigMetadata();
//    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
