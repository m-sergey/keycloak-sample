package me.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;

import org.keycloak.services.managers.AuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomSetCredentials implements Authenticator {

    private static final Logger LOG = LoggerFactory.getLogger(CustomSetCredentials.class);

    private static final String TPL_CODE = "custom-set-credentials.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.info("CustomSetCredentials authenticate");
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(),
                context.getRealm(), true);

        if (authResult == null) {
            LOG.info("CustomSetCredentials unauthenticated");
            context.attempted();
        } else {
            LOG.info("CustomSetCredentials authenticated");
            context.setUser(authResult.getUser());

            context.challenge(
                    context.form()
                            .setAttribute("realm", context.getRealm())
                            .createForm(TPL_CODE)
            );
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

        if(isCorrectPass) {
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
