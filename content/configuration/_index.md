---
title: "Configuration Options"
weight: 1
---

## `listen`

{{% details %}}
+ Environment Variable: `PROXY_LISTEN`
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
+ Environment Variable: `PROXY_LISTEN_HTTP`
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
+ Environment Variable: `PROXY_DISCOVERY_URL`
+ Example: `https://keycloak.localhost/auth/realms/applications` (refer to [demo](https://github.com/gogatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and gatekeeper is in reverse proxy mode
+ Default: None
+ Related: `skip-openid-provider-tls-verify`, `openid-provider-proxy`, `openid-provider-timeout`
{{% /details %}}

gatekeeper will get information about the authorization server through the
authorization server's `openid-configuration` well-known URI, according to
[RFC8414](https://tools.ietf.org/html/rfc8414).

gatekeeper will grab this metadata from `discovery-url` + `/.well-known/openid-configuration`
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
+ Environment Variable: `PROXY_CLIENT_ID`
+ Example: `whoami` (refer to [demo](https://github.com/gogatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and gatekeeper is in reverse proxy mode
+ Default: None
+ Related: `client-secret`
{{% /details %}}

`client-id` is the Client ID for an OAuth2 client (your app is the OAuth2 client, in
this case).

#### In reverse proxy mode

As part of the OAuth2 authorization code flow, gatekeeper will use `client-id` and
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

gatekeeper will use `client-id` and `client-secret` to authenticate with
the server to get tokens for outbound requests.

---

## `client-secret`

{{% details %}}
+ Environment Variable: `PROXY_CLIENT_SECRET`
+ Example: `932475b6-9748-41b8-8fd7-c6ce2d845ece` (refer to [demo](https://github.com/gogatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and gatekeeper is in reverse proxy mode
+ Default: None
+ Related: `client-id`
{{% /details %}}

`client-secret` is the client secret for an OAuth2 client (your app is the
OAuth2 client, in this case). This is used with `client-id` as a pair of
credentials. See `client-id` for how this is used.

---

## `redirection-url`

{{% details %}}
+ Environment Variable: `PROXY_REDIRECTION_URL`
+ Example: `932475b6-9748-41b8-8fd7-c6ce2d845ece` (refer to [demo](https://github.com/gogatekeeper/demo-docker-compose))
+ Required: Yes, unless `skip-token-verification` is set, and gatekeeper is in reverse proxy mode
+ Default: None
+ Related: `client-id`
{{% /details %}}

`client-secret` is the client secret for an OAuth2 client (your app is the
OAuth2 client, in this case). This is used with `client-id` as a pair of
credentials. See `client-id` for how this is used.

---

## `revocation-url`

{{% details %}}
+ Environment Variable: `PROXY_REVOCATION_URL`
+ Example: `https://keycloak.localhost/auth/realms/applications/protocol/openid-connect/logout`
+ Required: No. Will attempt to discover this url from OpenID discovery-url response
+ Default: None
+ Related: `discovery-url`
{{% /details %}}

If `revocation-url` is not specified, the `end_session_endpoint` of the OpenID
discovery-url response will be used as the `revocation-url`. If neither is
available, no logout at the authorization provider will be done.

`revocation-url` is used during the logout process. When the `/oauth/logout`
endpoint on gatekeeper is called, gatekeeper will request revocation of this
session's refresh token by doing an authenticated `POST` to this `revocation-url`
with the refresh token.

---

## `skip-openid-provider-tls-verify`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: false
+ Related: -
{{% /details %}}

If `skip-openid-provider-tls-verify` is set to `true`, gatekeeper will skip
verification of the authorization server's (or OpenID provider's, in this case)
certificate chain and host name.

gatekeeper will accept any certificate presented by the server and any host name
in that certificate.

This flag is directly used to configure `InsecureSkipVerify` in [golang's tls
package](https://golang.org/pkg/crypto/tls/).

---

## `openid-provider-proxy`

{{% details %}}
+ Environment Variable: None
+ Example: `http://proxy.example.com:80`
+ Required: No
+ Default: No proxy
+ Related: -
{{% /details %}}

Gatekeeper will use this proxy for requests to the OpenID provider, for example
to reach the discovery url, to get tokens, etc.

---

## `openid-provider-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `30s`
+ Related: -
{{% /details %}}

Timeout for pulling OpenID configuration from the OpenID provider. Will be
parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration).

---

## `base-uri`

{{% details %}}
+ Environment Variable: `PROXY_BASE_URI`
+ Example: `/base-uri`
+ Required: No
+ Default: `""`
+ Related: -
{{% /details %}}

`base-uri` is the the base URI of your app. This is where your app lives at the
domain, so if your domain is `https://www.example.com` and your app is at the
path `https://www.example.com/app`, then base URI should be `/app`.

This is used to

+ build oauth related paths, such as the `/logout` endpoint
+ set the [path for cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Path_attribute:~:text=Path%20attribute,-The),
  which determines which parts of your site the cookie is valid on, which in
  turn determines if the user remains authenticated as they visit different
  parts of the site

---

## `oauth-uri`

{{% details %}}
+ Environment Variable: `PROXY_OAUTH_URI`
+ Example: `/base-uri`
+ Required: No
+ Default: `"/oauth"`
+ Related: -
{{% /details %}}

This is the prefix for the OAuth endpoints on gatekeeper, such as (if the default `/oauth` is used, and `base-uri` is `""`)

+ `/oauth/authorization`: Redirects to the authorization server
+ `/oauth/callback`: Handles callback (response) from the authorization server
+ `/oauth/expired`: Checks if the token has expired
+ `/oauth/health`: The healthcheck endpoint for gatekeeper
+ `/oauth/logout?redirect=url`: Direct the browser here to log out
+ `/oauth/token`: Return the token in a json
+ `/oauth/login`: A generic endpoint for clients to perform a user credentials
  login to the authorization server

---

## `oauth-uri`

{{% details %}}
+ Environment Variable: `PROXY_OAUTH_URI`
+ Example: `/base-uri`
+ Required: No
+ Default: `"/oauth"`
+ Related: -
{{% /details %}}

This is the prefix for the OAuth endpoints on gatekeeper, such as (if the default `/oauth` is used, and `base-uri` is `""`)

+ `/oauth/authorization`: Redirects to the authorization server
+ `/oauth/callback`: Handles callback (response) from the authorization server
+ `/oauth/expired`: Checks if the token has expired
+ `/oauth/health`: The healthcheck endpoint for gatekeeper
+ `/oauth/logout?redirect=url`: Direct the browser here to log out
+ `/oauth/token`: Return the token in a json
+ `/oauth/login`: A generic endpoint for clients to perform a user credentials
  login to the authorization server

---

## `scopes`

{{% details %}}
+ Environment Variable: None
+ Example: (yaml/json list) `["offline", "foobar"]`
+ Required: No
+ Default: Always appends these: `["openid", "email", "profile"]`
+ Related: -
{{% /details %}}

These are the scopes that are requested when the client is redirected to the authorization server.

In Keycloak, these are the scopes that are either created as part of the
client, to client scopes in the realm. For Keycloak, scopes are strings tagged
to mappers. If requested by the client, the associated mappers will be applied
on the tokens.

---

## `upstream-url`

{{% details %}}
+ Environment Variable: `PROXY_UPSTREAM_URL`
+ Example: `http://whoami:80` (refer to [demo](https://github.com/gogatekeeper/demo-docker-compose))
+ Required: Yes
+ Default: None
+ Related: `upstream-ca`
{{% /details %}}

This tells gatekeeper how to contact the upstream (your app/service that is protected by gatekeeper)

---

## `upstream-ca`

{{% details %}}
+ Environment Variable: None
+ Example: `/tmp/path-to-ca-cert` (PEM encoded)
+ Required: No
+ Default: None (Will use system cert store)
+ Related: `upstream-url`
{{% /details %}}

This is the TLS CA certificate that will be used to verify TLS when communicating with the upstream.

---

## `resources`

{{% details %}}
+ Environment Variable: None
+ Example: Refer to [demo](https://github.com/gogatekeeper/demo-docker-compose)
+ Required: Yes
+ Default: None
+ Related: -
{{% /details %}}

These tell gatekeeper how to authenticate or authorize the resources at the upstream.

TODO add more details.

---

## `headers`

{{% details %}}
+ Environment Variable: None
+ Example:
    ```
    headers:
      x-foo-bar: baz
    ```
+ Required: No
+ Default: None
+ Related: -
{{% /details %}}

Add custom headers to the request that goes upstream. The headers will be capitalized:

```
x-foo-bar => X-Foo-Bar
X-FooBar => X-Foobar
X-FOO-BAR => X-Foo-Bar
```

---

## `preserve-host`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `preserve-host` is `true`, the `Host` header that gatekeeper receives will be forwarded to the upstream service. Otherwise, the `Host` header will be set to whatever gatekeeper uses to make the request to the upstream.

---

## `request-id-header`

{{% details %}}
+ Environment Variable: `PROXY_REQUEST_ID_HEADER`
+ Example: `"X-Request-Id"`
+ Required: No
+ Default: `"X-Request-Id"`
+ Related: `enable-request-id`
{{% /details %}}

The HTTP header name for the autogenerated request ID sent as a header to the upstream service. Will be added if `enable-request-id` is set to true.

---

## `enable-logout-redirect`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `true`, when the logout address is accessed, the user will be redirected to the identity provider on logout, with a `redirect_uri` pointing back to the gatekeeper service.

The identity provider can use `redirect_uri` to redirect the user back to gatekeeper again.

If `false`, when the logout address is accessed, the user will remain at gatekeeper's logout url.

---

## `enable-default-deny`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `resources`
{{% /details %}}

Used in conjunction with `resources` for authorization.

If set, gatekeeper will deny all requests to the upstream by default. This can then be relaxed with definition of `resources`.

---

## `enable-encrypted-token`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `force-encrypted-cookie`, `encryption-key`
{{% /details %}}

If set, gatekeeper will

+ Encrypt the access token in the cookie that is set for the browser with `encryption-key`
+ Assume that incoming access tokens in the `Authorization` header are also
  encrypted, and will decrypt the token before using it

---

## `force-encrypted-cookie`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `enable-encrypted-token`, `encryption-key`
{{% /details %}}

Same as `enable-encrypted-token`. TODO confirm this.

---

## `enable-logging`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If set, requests to gatekeeper are logged. Here's a sample of the information that is logged:

```
2020-12-26T06:21:38.851Z        info    src/middleware.go:146   client request  {"latency": 0.000209767, "status": 303, "bytes": 322, "client_ip": "172.18.0.2:39368", "method": "GET", "path": "/oauth/authorize"}
```

`raw path` is also logged if it is different from `path` and is not `""`. See [go docs](https://golang.org/pkg/net/url/) for the difference between `Path` and `RawPath`.

---

## `enable-json-logging`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If set, logging is formatted in json.

If the regular log is like this,

```
2020-12-26T06:21:38.851Z        info    src/middleware.go:146   client request  {"latency": 0.000209767, "status": 303, "bytes": 322, "client_ip": "172.18.0.2:39368", "method": "GET", "path": "/oauth/authorize"}
```

the json version is like this.

```
{"level":"info","ts":"2020-12-26T06:21:38.851Z","caller":"src/middleware.go:146","msg":"client request","latency":0.000209767,"status":303,"bytes":322,"client_ip":"172.18.0.2:39368","method":"GET","path":"/oauth/authorize"}
```

---

## `enable-forwarding`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Sets gatekeeper in a forwarding proxy mode, for signing outbound requests. This is mutually exclusive with the default reverse proxy mode.

---

## `enable-security-filter`

{{% details %}}
+ Environment Variable: `PROXY_ENABLE_SECURITY_FILTER`
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Enables a bunch of security checks on the request using middleware. TODO add more detail.

---

## `enable-refresh-tokens`

{{% details %}}
+ Environment Variable: `PROXY_ENABLE_REFRESH_TOKEN`
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Set this to get gatekeeper to handle refreshing of access tokens. Otherwise, gatekeeper will just re-authenticate with the authorization server whenever the access token expires.

---
