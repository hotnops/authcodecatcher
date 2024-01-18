# authcodecatcher
A server for exchanging OAuth Codes for Tokens

## Description
If an open or hijackable redirect URI is discovered for an entra application, authcodecatcher can serve as a server at the hijackable URL to catch auth codes and exchange them for tokens. The user will be redirected to the configurable landing page. PKCE is supported.

## Installation
```
pip install authcodecatcher
```

## Usage
First, an SSL certificate needs to be created if you don't have one already
```
openssl req -new -x509 -keyout cert.pem -out cert.pem -days 365 -nodes
```

Next, run the module with the required arguments
```
python3 -m authcodecatcher.server --client-id <ID of hijackable app registration> --tenant-id <target tenant ID> --redirect-uri <The hijackable URI that you control> --port <The port to listen on> --cert-file <The PEM certificate file created in the previous step>
```

Lastly, generate a URL that will be sent to the target
```
curl https://localhost:1337/generateurl
```

The output will be JSON with a URL that contains the authorization endpoint. If an authenticated user navigates to this URL, authcodecatcher will obtain the auth code and exchange it for an access token. All access tokens are saved to a JSON file 'tokens.json' by default.

## Command Options
### --redirect-uri
The hijackable URI that the attacker controls. Must be listed in the application registration.
### --scope
The requested scope of the JWT. Defaults to *https://graph.microsoft.com/.default+offline_access*
### --urlpath
The path of the redirect-uri. For example, if the redirect-uri is *https://test.example.com/oauth/token*, then the --urlpath should be set to */oauth/token*.
### --port
The port on which the server will listen
### --client-id
The client ID (application ID) of the targeted Entra application.
### --tenant-id
The target tenant ID
### --output-file
The file that authcodecatcher will write tokens and pkce codes to.
### --cert-file
The certificate file to use for SSL
### --landing-page
The page that the user will be redirected to after the code exchange. Defaults to *https://en.wikipedia.org/wiki/Snallygaster*.