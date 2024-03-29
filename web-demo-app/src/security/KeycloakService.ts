import Keycloak from "keycloak-js";

const keycloakInstance = new Keycloak();

interface CallbackOneParam<T1 = void, T2 = void> {
  (param1: T1): T2;
}
/**
 * Initializes Keycloak instance and calls the provided callback function if successfully authenticated.
 *
 * @param onAuthenticatedCallback
 */
// const Login = (onAuthenticatedCallback: CallbackOneParam) => {
const Login = () => {
  keycloakInstance
    .init({ onLoad: "login-required" })
    .then(function (authenticated) {
        authenticated ? console.log("log in success") : alert("non authenticated");
    //   authenticated ? onAuthenticatedCallback() : alert("non authenticated");
    })
    .catch((e) => {
      console.dir(e);
      console.log(`keycloak init exception: ${e}`);
    });
};

const UserName = (): string | undefined =>
  keycloakInstance?.tokenParsed?.preferred_username;

const Token = (): string | undefined => keycloakInstance?.token;

const LogOut = () => keycloakInstance.logout();

const RefreshToken = (): string | undefined => keycloakInstance?.refreshToken;

const KeyCloakService = {
  CallLogin: Login,
  GetUserName: UserName,
  GetAccesToken: Token,
  GetRefreshToken: RefreshToken,
  CallLogOut: LogOut,  
};

export default KeyCloakService;
