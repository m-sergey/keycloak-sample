package me.keycloak.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KafkaEventListenerProvider implements EventListenerProvider {

    private static final Logger LOG = LoggerFactory.getLogger(KafkaEventListenerProvider.class);
    private final String eventTopic = "events";
    private final String adminEventTopic = "admin_events";

    private final ObjectMapper mapper;
    private final EventProducer producer;

    protected final KeycloakSession session;

    public KafkaEventListenerProvider(KeycloakSession session) {
        producer = new EventProducer();
        mapper = new ObjectMapper();
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        LOG.info("Event " + event.getType() + " " + event.getDetails());

        if (EventType.LOGIN.equals(event.getType())
                && session.getContext() != null
                && session.getContext().getRequestHeaders() != null) {
            var details = event.getDetails();
            if(details != null) {
                details.putIfAbsent("User-Agent", session.getContext().getRequestHeaders().getHeaderString("User-Agent"));
            } else {
                // TBD
            }
        }

        String value;
        try {
            value = mapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            LOG.error("JsonProcessingException: {}", e);
            throw new RuntimeException(e);
        }

        LOG.info("Kafka record^ "  + value);

        producer.publishEvent(eventTopic, event.getSessionId(), value);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        LOG.info("Event " + event.getOperationType().name() + " " + event.toString());

        String value;
        try {
            value = mapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            LOG.error("JsonProcessingException: {}", e);
            throw new RuntimeException(e);
        }

        LOG.info("Kafka record^ "  + value);

        producer.publishEvent(eventTopic, event.getRealmId(), value);
    }

    @Override
    public void close() {

    }
}
