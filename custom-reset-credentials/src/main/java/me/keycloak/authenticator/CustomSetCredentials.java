package me.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.*;

import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.representations.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;

public class CustomSetCredentials implements Authenticator {

    private static final Logger LOG = LoggerFactory.getLogger(CustomSetCredentials.class);

    private static final String TPL_CODE = "custom-set-credentials.ftl";

    private static final String AUDIENCE = "reset-password";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.info("CustomSetCredentials authenticate");

        var session = context.getSession();
        var request = context.getSession().getContext().getUri();
        var params = request.getQueryParameters(true);
        var subjectToken = params.getFirst("token");

        try {
            JWSInput jws = new JWSInput(subjectToken);
            var headers = jws.getHeader();

            SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, headers.getAlgorithm().name()).verifier(headers.getKeyId());

            if (!signatureVerifier.verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature())) {
                LOG.info("CustomSetCredentials unauthenticated (invalid signature)");
                context.attempted();
                return;
            }

            JsonWebToken jwt = jws.readJsonContent(JsonWebToken.class);

            if(!jwt.isActive()) {
                LOG.info("CustomSetCredentials unauthenticated (expired token)");
                context.attempted();
                return;
            }

            if(!AUDIENCE.equals(jwt.getAudience()[0])) {
                LOG.info("CustomSetCredentials unauthenticated (incorrect aud)");
                context.attempted();
                return;
            }

            var user = session.users().getUserById(context.getRealm(), jwt.getSubject());

            if (user == null) {
                LOG.info("CustomSetCredentials unauthenticated (user not found)");
                context.attempted();
                return;
            }

            LOG.info("CustomSetCredentials authenticated");
            context.setUser(user);

            context.challenge(
                    context.form()
                            .setAttribute("realm", context.getRealm())
                            .createForm(TPL_CODE)
            );
        } catch (JWSInputException | VerificationException | UnsupportedEncodingException e) {
            LOG.error("CustomSetCredentials: {} \n {}", e.getMessage(), e.fillInStackTrace());
            context.attempted();
            return;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        LOG.info("CustomSetCredentials action");

        String currentPassword = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("currentPassword");

        String newPassword = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("newPassword");

        var credManager = context.getSession().userCredentialManager();

        boolean isCorrectPass = credManager.isValid(context.getRealm(), context.getUser(), UserCredentialModel.password(currentPassword));
        LOG.info("Result for {} is {}", context.getUser().getUsername(), isCorrectPass);

        var policyManagerProvider = context.getSession().getProvider(PasswordPolicyManagerProvider.class);
        PolicyError error = policyManagerProvider.validate(context.getRealm(), context.getUser(), newPassword);

        if(isCorrectPass && error == null) {
            credManager.updateCredential(context.getRealm(), context.getUser(), UserCredentialModel.password(newPassword));
            context.success();
        } else {
            context.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                            .setAttribute("realm", context.getRealm())
                            .setError("invalidCredentials")
                            .createForm(TPL_CODE)
            );
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {
    }
}
