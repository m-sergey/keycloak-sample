package me.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.services.managers.AuthenticationManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomResetCredentials implements Authenticator {

    private static final Logger LOG = LoggerFactory.getLogger(CustomResetCredentials.class);

    private static final String TPL_CODE = "custom-reset-credentials.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        LOG.info("CustomResetCredentials authenticate");
        context.challenge(
                context.form()
                        .setAttribute("realm", context.getRealm())
                        .createForm(TPL_CODE)
        );
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        LOG.info("CustomResetCredentials action");

        String username = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("username");

        String secretAnswer = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("secretAnswer");

        String newPassword = context.getHttpRequest()
                .getDecodedFormParameters()
                .getFirst("newPassword");

        if (username == null || secretAnswer == null) {
            context.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                            .setAttribute("realm", context.getRealm())
                            .setError("invalidCredentials")
                            .createForm(TPL_CODE)
            );
            return;
        }

        LOG.info("Reset password request for {}", username);

        // TO-DO: Find way to find user using only username
        var user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);

        if (user == null) {
            context.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                            .setAttribute("realm", context.getRealm())
                            .setError("invalidCredentials")
                            .createForm(TPL_CODE)
            );
            return;
        }

        LOG.info("{} was found", username);

        var credManager = context.getSession().userCredentialManager();
        var values = user.getAttribute("secret-answer");

        LOG.info("Found {} attributes of {}", values.size(), username);

        var policyManagerProvider = context.getSession().getProvider(PasswordPolicyManagerProvider.class);
        PolicyError error = policyManagerProvider.validate(context.getRealm(), user, newPassword);

        if (values.size() == 1
                && values.get(0).equals(secretAnswer)
                && error == null) {
            credManager.updateCredential(context.getRealm(), user, UserCredentialModel.password(newPassword));
            LOG.info("Password was updated for {} ", username);
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
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {
    }
}
