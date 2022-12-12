


## Get access token

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=test' \
--data-urlencode 'password=reset' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=password'
````


## Token exchange (for reset-password)

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=account' \
--data-urlencode 'audience=reset-password' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=???' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'
````

## Token exchange (with groups)

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=???' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'
--data-urlencode 'groups=group1'
````

## Set new password

Open URL in browser:

```
http://localhost:8080/realms/Clients/login-actions/reset-credentials?client_id=accounts&token=<reset-password token>
```

## Map user's id in IT systems into claim "ids"

Add attributes for user with prefix "ids." (Tab Attributes)

