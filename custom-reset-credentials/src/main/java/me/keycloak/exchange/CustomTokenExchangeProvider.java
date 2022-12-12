package me.keycloak.exchange;

import com.google.common.base.Strings;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ExchangeExternalToken;
import org.keycloak.broker.provider.ExchangeTokenToIdentityProviderToken;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.IdentityProviderMapperSyncModeDelegate;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Base64Url;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.oidc.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.TokenEndpoint.TokenExchangeSamlProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_ID;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_USERNAME;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * Custom token exchange with scopes support and without SAML support
 */
public class CustomTokenExchangeProvider implements TokenExchangeProvider {

    private static final Logger logger = Logger.getLogger(CustomTokenExchangeProvider.class);

    private MultivaluedMap<String, String> formParams;
    private KeycloakSession session;
    private Cors cors;
    private RealmModel realm;
    private ClientModel client;
    private EventBuilder event;
    private ClientConnection clientConnection;
    private HttpHeaders headers;
    private TokenManager tokenManager;
    private Map<String, String> clientAuthAttributes;

    @Override
    public boolean supports(TokenExchangeContext context) {
        String requestedTokenType = context.getFormParams().getFirst(OAuth2Constants.REQUESTED_TOKEN_TYPE);

        switch (requestedTokenType) {
            case OAuth2Constants.ACCESS_TOKEN_TYPE:
            case OAuth2Constants.REFRESH_TOKEN_TYPE:
                return true;
        }

        logger.debugf("Unsupported token type: '%s'", requestedTokenType);
        return false;
    }

    @Override
    public void close() {
    }

    @Override
    public Response exchange(TokenExchangeContext context) {
        this.formParams = context.getFormParams();
        this.session = context.getSession();
        this.cors = (Cors) context.getCors();
        this.realm = context.getRealm();
        this.client = context.getClient();
        this.event = context.getEvent();
        this.clientConnection = context.getClientConnection();
        this.headers = context.getHeaders();
        this.tokenManager = (TokenManager) context.getTokenManager();
        this.clientAuthAttributes = context.getClientAuthAttributes();
        return tokenExchange();
    }

    protected Response tokenExchange() {

        UserModel tokenUser = null;
        UserSessionModel tokenSession = null;
        AccessToken token = null;

        String subjectToken = formParams.getFirst(OAuth2Constants.SUBJECT_TOKEN);
        if (subjectToken != null) {
            String subjectTokenType = formParams.getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
            String realmIssuerUrl = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
            String subjectIssuer = formParams.getFirst(OAuth2Constants.SUBJECT_ISSUER);

            if (subjectIssuer == null && OAuth2Constants.JWT_TOKEN_TYPE.equals(subjectTokenType)) {
                try {
                    JWSInput jws = new JWSInput(subjectToken);
                    JsonWebToken jwt = jws.readJsonContent(JsonWebToken.class);
                    subjectIssuer = jwt.getIssuer();
                } catch (JWSInputException e) {
                    event.detail(Details.REASON, "unable to parse jwt subject_token");
                    event.error(Errors.INVALID_TOKEN);
                    throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid token type, must be access token", Response.Status.BAD_REQUEST);

                }
            }

            /*
             * TODO Should implement this part if needs support of external provider
             */
            /*
            if (subjectIssuer != null && !realmIssuerUrl.equals(subjectIssuer)) {
                event.detail(OAuth2Constants.SUBJECT_ISSUER, subjectIssuer);
                return exchangeExternalToken(subjectIssuer, subjectToken);
            }
            */

            if (subjectTokenType != null && !subjectTokenType.equals(OAuth2Constants.ACCESS_TOKEN_TYPE)) {
                event.detail(Details.REASON, "subject_token supports access tokens only");
                event.error(Errors.INVALID_TOKEN);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid token type, must be access token", Response.Status.BAD_REQUEST);

            }

            AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(session, realm, session.getContext().getUri(), clientConnection, true, true, null, false, subjectToken, headers);
            if (authResult == null) {
                event.detail(Details.REASON, "subject_token validation failure");
                event.error(Errors.INVALID_TOKEN);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid token", Response.Status.BAD_REQUEST);
            }

            tokenUser = authResult.getUser();
            tokenSession = authResult.getSession();
            token = authResult.getToken();
        }

        String requestedSubject = formParams.getFirst(OAuth2Constants.REQUESTED_SUBJECT);
        boolean disallowOnHolderOfTokenMismatch = true;

        if (requestedSubject != null) {
            event.detail(Details.REQUESTED_SUBJECT, requestedSubject);
            UserModel requestedUser = session.users().getUserByUsername(realm, requestedSubject);
            if (requestedUser == null) {
                requestedUser = session.users().getUserById(realm, requestedSubject);
            }

            if (requestedUser == null) {
                // We always returned access denied to avoid username fishing
                event.detail(Details.REASON, "requested_subject not found");
                event.error(Errors.NOT_ALLOWED);
                throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);

            }

            if (token != null) {
                event.detail(Details.IMPERSONATOR, tokenUser.getUsername());
                // for this case, the user represented by the token, must have permission to impersonate.
                AdminAuth auth = new AdminAuth(realm, token, tokenUser, client);
                if (!AdminPermissions.evaluator(session, realm, auth).users().canImpersonate(requestedUser, client)) {
                    event.detail(Details.REASON, "subject not allowed to impersonate");
                    event.error(Errors.NOT_ALLOWED);
                    throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);
                }
            } else {
                // no token is being exchanged, this is a direct exchange.  Client must be authenticated, not public, and must be allowed
                // to impersonate
                if (client.isPublicClient()) {
                    event.detail(Details.REASON, "public clients not allowed");
                    event.error(Errors.NOT_ALLOWED);
                    throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);

                }
                if (!AdminPermissions.management(session, realm).users().canClientImpersonate(client, requestedUser)) {
                    event.detail(Details.REASON, "client not allowed to impersonate");
                    event.error(Errors.NOT_ALLOWED);
                    throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);
                }

                // see https://issues.redhat.com/browse/KEYCLOAK-5492
                disallowOnHolderOfTokenMismatch = false;
            }

            tokenSession = session.sessions().createUserSession(realm, requestedUser, requestedUser.getUsername(), clientConnection.getRemoteAddr(), "impersonate", false, null, null);
            if (tokenUser != null) {
                tokenSession.setNote(IMPERSONATOR_ID.toString(), tokenUser.getId());
                tokenSession.setNote(IMPERSONATOR_USERNAME.toString(), tokenUser.getUsername());
            }

            tokenUser = requestedUser;
        }

        String requestedIssuer = formParams.getFirst(OAuth2Constants.REQUESTED_ISSUER);
        if (requestedIssuer == null) {
            return exchangeClientToClient(tokenUser, tokenSession, token, disallowOnHolderOfTokenMismatch);
        } else {
            try {
                return exchangeToIdentityProvider(tokenUser, tokenSession, requestedIssuer);
            } finally {
                if (subjectToken == null) { // we are naked! So need to clean up user session
                    try {
                        session.sessions().removeUserSession(realm, tokenSession);
                    } catch (Exception ignore) {

                    }
                }
            }
        }
    }

    protected Response exchangeToIdentityProvider(UserModel targetUser, UserSessionModel targetUserSession, String requestedIssuer) {
        event.detail(Details.REQUESTED_ISSUER, requestedIssuer);
        IdentityProviderModel providerModel = realm.getIdentityProviderByAlias(requestedIssuer);
        if (providerModel == null) {
            event.detail(Details.REASON, "unknown requested_issuer");
            event.error(Errors.UNKNOWN_IDENTITY_PROVIDER);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Invalid issuer", Response.Status.BAD_REQUEST);
        }

        IdentityProvider provider = IdentityBrokerService.getIdentityProvider(session, realm, requestedIssuer);
        if (!(provider instanceof ExchangeTokenToIdentityProviderToken)) {
            event.detail(Details.REASON, "exchange unsupported by requested_issuer");
            event.error(Errors.UNKNOWN_IDENTITY_PROVIDER);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Issuer does not support token exchange", Response.Status.BAD_REQUEST);
        }
        if (!AdminPermissions.management(session, realm).idps().canExchangeTo(client, providerModel)) {
            event.detail(Details.REASON, "client not allowed to exchange for requested_issuer");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);
        }
        Response response = ((ExchangeTokenToIdentityProviderToken) provider).exchangeFromToken(session.getContext().getUri(), event, client, targetUserSession, targetUser, formParams);
        return cors.builder(Response.fromResponse(response)).build();

    }

    protected Response exchangeClientToClient(UserModel targetUser, UserSessionModel targetUserSession,
                                              AccessToken token, boolean disallowOnHolderOfTokenMismatch) {
        String requestedTokenType = formParams.getFirst(OAuth2Constants.REQUESTED_TOKEN_TYPE);
        if (requestedTokenType == null) {
            requestedTokenType = OAuth2Constants.REFRESH_TOKEN_TYPE;
        } else if (!requestedTokenType.equals(OAuth2Constants.ACCESS_TOKEN_TYPE) &&
                !requestedTokenType.equals(OAuth2Constants.REFRESH_TOKEN_TYPE) &&
                !requestedTokenType.equals(OAuth2Constants.SAML2_TOKEN_TYPE)) {
            event.detail(Details.REASON, "requested_token_type unsupported");
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "requested_token_type unsupported", Response.Status.BAD_REQUEST);

        }

        String audience = formParams.getFirst(OAuth2Constants.AUDIENCE);
        ClientModel tokenHolder = token == null ? null : realm.getClientByClientId(token.getIssuedFor());
        ClientModel targetClient = client;

        if (audience != null) {
            targetClient = realm.getClientByClientId(audience);
            if (targetClient == null) {
                event.detail(Details.REASON, "audience not found");
                event.error(Errors.CLIENT_NOT_FOUND);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT, "Audience not found", Response.Status.BAD_REQUEST);

            }
        }

        if (targetClient.isConsentRequired()) {
            event.detail(Details.REASON, "audience requires consent");
            event.error(Errors.CONSENT_DENIED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT, "Client requires user consent", Response.Status.BAD_REQUEST);
        }

        boolean isClientTheAudience = client.equals(targetClient);

        if (isClientTheAudience) {
            if (client.isPublicClient()) {
                // public clients can only exchange on to themselves if they are the token holder
                forbiddenIfClientIsNotTokenHolder(disallowOnHolderOfTokenMismatch, tokenHolder);
            } else if (!client.equals(tokenHolder)) {
                // confidential clients can only exchange to themselves if they are within the token audience
                forbiddenIfClientIsNotWithinTokenAudience(token, tokenHolder);
            }
        } else {
            if (client.isPublicClient()) {
                // public clients can not exchange tokens from other client
                forbiddenIfClientIsNotTokenHolder(disallowOnHolderOfTokenMismatch, tokenHolder);
            }
            if (!AdminPermissions.management(session, realm).clients().canExchangeTo(client, targetClient)) {
                event.detail(Details.REASON, "client not allowed to exchange to audience");
                event.error(Errors.NOT_ALLOWED);
                throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client not allowed to exchange", Response.Status.FORBIDDEN);
            }
        }

        String scope = formParams.getFirst(OAuth2Constants.SCOPE);
        String groups = formParams.getFirst("groups");

        switch (requestedTokenType) {
            case OAuth2Constants.ACCESS_TOKEN_TYPE:
            case OAuth2Constants.REFRESH_TOKEN_TYPE:
                return exchangeClientToOIDCClient(targetUser, targetUserSession, requestedTokenType, targetClient, audience, scope, groups);
//            case OAuth2Constants.SAML2_TOKEN_TYPE:
//                return exchangeClientToSAML2Client(targetUser, targetUserSession, requestedTokenType, targetClient, audience, scope);
        }

        throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "requested_token_type unsupported", Response.Status.BAD_REQUEST);
    }

    private void forbiddenIfClientIsNotWithinTokenAudience(AccessToken token, ClientModel tokenHolder) {
        if (token != null && !token.hasAudience(client.getClientId())) {
            event.detail(Details.REASON, "client is not within the token audience");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client is not within the token audience", Response.Status.FORBIDDEN);
        }
    }

    private void forbiddenIfClientIsNotTokenHolder(boolean disallowOnHolderOfTokenMismatch, ClientModel tokenHolder) {
        if (disallowOnHolderOfTokenMismatch && !client.equals(tokenHolder)) {
            event.detail(Details.REASON, "client is not the token holder");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "Client is not the holder of the token", Response.Status.FORBIDDEN);
        }
    }

    protected Response exchangeClientToOIDCClient(UserModel targetUser, UserSessionModel targetUserSession, String requestedTokenType,
                                                  ClientModel targetClient, String audience, String scope,
                                                  String groups) {
        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(targetClient);

        authSession.setAuthenticatedUser(targetUser);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        event.session(targetUserSession);

        AuthenticationManager.setClientScopesInSession(authSession);
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(this.session, targetUserSession, authSession);

        updateUserSessionFromClientAuth(targetUserSession);

        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager.responseBuilder(realm, targetClient, event, this.session, targetUserSession, clientSessionCtx)
                .generateAccessToken();
        responseBuilder.getAccessToken().issuedFor(client.getClientId());

        if (audience != null) {
            responseBuilder.getAccessToken().addAudience(audience);
        }

        if (requestedTokenType.equals(OAuth2Constants.REFRESH_TOKEN_TYPE)
                && OIDCAdvancedConfigWrapper.fromClientModel(client).isUseRefreshToken()) {
            responseBuilder.generateRefreshToken();
            responseBuilder.getRefreshToken().issuedFor(client.getClientId());
        }

        String scopeParam = clientSessionCtx.getClientSession().getNote(OAuth2Constants.SCOPE);
        if (TokenUtil.isOIDCRequest(scopeParam)) {
            responseBuilder.generateIDToken().generateAccessTokenHash();
        }

        /*
         * Add groups to token
         */
        if (!Strings.isNullOrEmpty(groups)) {
            logger.infof("user's group %s", targetUser.getGroups());
            var requestedGroups = new HashSet<String>(Arrays.asList(groups.split(",")));
            var grantedGroups = targetUser
                    .getGroupsStream()
                    .filter(g -> requestedGroups.contains(g.getName()))
                    .map(GroupModel::getName)
                    .collect(Collectors.toSet());
            logger.infof("granted group %s", grantedGroups);
            responseBuilder.getAccessToken().setOtherClaims("groups", grantedGroups);
        }

        AccessTokenResponse res = responseBuilder.build();
        event.detail(Details.AUDIENCE, targetClient.getClientId());

        event.success();

        return cors.builder(Response.ok(res, MediaType.APPLICATION_JSON_TYPE)).build();
    }

    // TODO: move to utility class
    private void updateUserSessionFromClientAuth(UserSessionModel userSession) {
        for (Map.Entry<String, String> attr : clientAuthAttributes.entrySet()) {
            userSession.setNote(attr.getKey(), attr.getValue());
        }
    }
}
