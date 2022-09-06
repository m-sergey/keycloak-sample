


## Get access token

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=test' \
--data-urlencode 'password=reset' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=password'
````


## Token exchange

````
curl --location --request POST 'http://localhost:8080/realms/Clients/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=account' \
--data-urlencode 'audience=reset-password' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=???' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token'
````
