---
title: "Configuration Options"
weight: 1
---

## `listen`

{{% details %}}
+ Environment Variable: `LISTEN`
+ Example: `:80`
+ Required: Yes
+ Default: None
+ Related: `listen-http`
{{% /details %}}

`listen` configures the main listening interface (compare with `listen-http`). Examples for

+ regular `http(s)`:
    + use `:80` or `:443` to listen on all interfaces
    + `127.0.0.1:443` to only listen on a certain interface
+ unix socket: `unix:///tmp/echo.sock` (add the prefix `unix://`)

{{% notice info %}}
This config is passed to golang's `net.Listen()`, so use strings acceptable by `address`.
{{% /notice %}}

---

## `listen-http`

{{% details %}}
+ Environment Variable: `LISTEN_HTTP`
+ Example: `:80`
+ Required: Yes
+ Default: None
+ Related: `listen`
{{% /details %}}

`listen-http` configures the secondary listening interface.
This listener has no TLS support, and uses the same configuration syntax as `listen`.

{{% notice info %}}
Usually, we only use `listen` and not set `listen-http`.
{{% /notice %}}

---

## `discovery-url`

{{% details %}}
+ Environment Variable: `DISCOVERY_URL`
+ Example: `https://keycloak.localhost/auth/realms/applications` (refer to [demo](https://github.com/go-gatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and louketo is in reverse proxy mode
+ Default: None
+ Related: `skip-openid-provider-tls-verify`, `openid-provider-proxy`, `openid-provider-timeout`
{{% /details %}}

louketo will get information about the authorization server through the
authorization server's `openid-configuration` well-known URI, according to
[RFC8414](https://tools.ietf.org/html/rfc8414).

louketo will grab this metadata from `discovery-url` + `/.well-known/openid-configuration`
as is registered with [IANA](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)

Specify `discovery-url` without `/.well-known/openid-configuration`.

Here are links to information about `discovery-url`s for some other OAuth providers

+ [Google Identity Platform](https://developers.google.com/identity/protocols/oauth2/openid-connect)
+ [Auth0](https://auth0.com/docs/protocols/configure-applications-with-oidc-discovery)
+ [IdentityServer4](https://docs.identityserver.io/en/dev/endpoints/discovery.html)
+ [PingFederate](https://docs.pingidentity.com/bundle/pingfederate-90/page/concept_openIdConnectMetadataEndpoint.html)

---

## `client-id`

{{% details %}}
+ Environment Variable: `CLIENT_ID`
+ Example: `whoami` (refer to [demo](https://github.com/go-gatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and louketo is in reverse proxy mode
+ Default: None
+ Related: `client-secret`
{{% /details %}}

`client-id` is the Client ID for an OAuth2 client (your app is the OAuth2 client, in
this case).

#### In reverse proxy mode

As part of the OAuth2 authorization code flow, louketo will use `client-id` and
`client-secret` to authenticate with the server when it needs to

+ exchange the authorization code for tokens
+ refresh the access token

The client ID and secret are also used to invoke the revocation URL at the
authorization server.

If the login handler is enabled (`enable-login-handler`), the credentials are
also used to login at the authorization provider using the OAuth2 Resource
Owner Password Credentials flow.

`client-id` is also used to check access tokens to ensure that `client-id` is
among the audiences in the `aud` field of the token.

#### In forward-signing proxy mode

louketo will use louketo `client-id` and `client-secret` to authenticate with
the server to get tokens for outbound requests.

---

## `client-secret`

{{% details %}}
+ Environment Variable: `CLIENT_SECRET`
+ Example: `932475b6-9748-41b8-8fd7-c6ce2d845ece` (refer to [demo](https://github.com/go-gatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and louketo is in reverse proxy mode
+ Default: None
+ Related: `client-id`
{{% /details %}}

`client-secret` is the client secret for an OAuth2 client (your app is the
OAuth2 client, in this case). This is used with `client-id` as a pair of
credentials. See `client-id` for how this is used.

---

## `redirection-url`

{{% details %}}
+ Environment Variable: `REDIRECTION_URL`
+ Example: `932475b6-9748-41b8-8fd7-c6ce2d845ece` (refer to [demo](https://github.com/go-gatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and louketo is in reverse proxy mode
+ Default: None
+ Related: `client-id`
{{% /details %}}

`client-secret` is the client secret for an OAuth2 client (your app is the
OAuth2 client, in this case). This is used with `client-id` as a pair of
credentials. See `client-id` for how this is used.

---

## `revocation-url`

{{% details %}}
+ Environment Variable: `REVOCATION_URL`
+ Example: `https://keycloak.localhost/auth/realms/applications/protocol/openid-connect/logout`
+ Required: No. Will attempt to discover this url from OpenID discovery-url response
+ Default: None
+ Related: `discovery-url`
{{% /details %}}

If `revocation-url` is not specified, the `end_session_endpoint` of the OpenID
discovery-url response will be used as the `revocation-url`. If neither is
available, no logout at the authorization provider will be done.

`revocation-url` is used during the logout process. When the `/oauth/logout`
endpoint on louketo is called, louketo will request revocation of this
session's refresh token by doing an authenticated `POST` to this `revocation-url`
with the refresh token.

---
