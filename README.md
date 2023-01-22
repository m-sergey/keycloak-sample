## Working with Keycloak

### Get access token

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=test' \
--data-urlencode 'password=reset' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=password'
````


### Token exchange (for reset-password)

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=account' \
--data-urlencode 'audience=reset-password' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=???' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'
````

### Token exchange (with groups)

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=???' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'
--data-urlencode 'groups=group1'
````

### Set new password

Open URL in browser:

```
http://localhost:8080/realms/Clients/login-actions/reset-credentials?client_id=accounts&token=<reset-password token>
```

### Map user's id in IT systems into claim "ids"

Add attributes for user with prefix "ids." (Tab Attributes)

## Sample web application

### Configuration 

You have to set up your enviroment variables in ___*./web-demo-app/public/keycloak.json*___, where

"realm" - Keycloak realm name

"auth-server-url" - Keycloak base URL

"resource" - client in the selected realm

Example:
```
{
    "realm": "Clients",
    "auth-server-url": "http://localhost:8080/",
    "ssl-required": "external",
    "resource": "webapp",
    "public-client": true,
    "confidential-port": 0
}
```

### Build Docker image

```
>  docker build -t keycloak-web-demo .
```

### Run web demo app in Docker

```
> docker run -d --name demo-app -p 8081:80 keycloak-web-demo
```
