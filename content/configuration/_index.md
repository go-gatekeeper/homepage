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
+ Default: `true`
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

Sets gatekeeper in a forward proxy mode, for signing outbound requests. This is mutually exclusive with the default reverse proxy mode.

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

## `enable-session-cookies`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If this is set, gatekeeper will define the lifetime of the cookies (containing access and refresh tokens) to "Session", indicating that they should be cleared when the browser closes.

The actual behavior, however, depends on how the browser is configured. Some browsers restore sessions when restarting, so session cookies might get restored. See [MDN: Lifetime of a cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Define_the_lifetime_of_a_cookie).

If this is set to `false`, the cookies will be set to expire when the token expires.

---

## `enable-login-handler`

{{% details %}}
+ Environment Variable: `PROXY_ENABLE_LOGIN_HANDLER`
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If this is set, the login handler will be enabled.

By default, the login handler listens at `/oauth/login`, and looks for `username` and `password` in `POST` data from the browser. It will then obtain an access token and refresh token from the authorization server and then manage the tokens for the user.

---

## `enable-token-header`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If this is set, the access token will be added to the request going to the upstream service as the `X-Auth-Token` header.

---

## `enable-authorization-header`

{{% details %}}
+ Environment Variable: `PROXY_ENABLE_AUTHORIZATION_HEADER`
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If this is set, the access token will be added to the request going to the upstream service as the `Authorization` header:

```
Authorization: Bearer <access_token>
```

---

## `enable-authorization-cookies`

{{% details %}}
+ Environment Variable: `PROXY_ENABLE_AUTHORIZATION_COOKIES`
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If this is set, gatekeeper will add the authorization cookies to the upstream proxy request (containing access and refresh tokens).

---

## `enable-https-redirect`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `enable-security-filter`
{{% /details %}}

If this is set, gatekeeper will redirect all http requests to https.

`enable-security-filter` has to be `true` for this to work.

---

## `enable-profiling`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Setting this turns on profiling. TODO add more information about profiling.

---

## `enable-metrics`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Setting this enables the prometheus metrics collector at `/oauth/metrics`. TODO add more information about metrics.

---

## `filter-browser-xss`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `enable-security-filter`
{{% /details %}}

Setting this adds the `X-XSS-Protection` header for the browser with `mode=block`. More information [on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

`enable-security-filter` has to be `true` to enable this.

---

## `filter-content-nosniff`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `enable-security-filter`
{{% /details %}}

Setting this adds the `X-Content-Type-Options` header for the browser with the value `nosniff`. More information [on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

`enable-security-filter` has to be `true` to enable this.

---

## `filter-frame-deny`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `enable-security-filter`
{{% /details %}}

Setting this adds the `X-Frame-Options` header with the value of `DENY`. More information [on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

`enable-security-filter` has to be `true` to enable this.

---

## `content-security-policy`

{{% details %}}
+ Environment Variable: None
+ Example: `default-src 'self'`
+ Required: No
+ Default: Unspecified
+ Related: `enable-security-filter`
{{% /details %}}

This configuration option allows you to specify your Content Security Policy. More information [on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

`enable-security-filter` has to be `true` to enable this.

---

## `localhost-metrics`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Enforces that the metrics page can only been requested from the loopback interface, on `localhost`.

---

## `enable-compression`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Enables gzip compression for response from gatekeeper to browser.

---

## `access-token-duration`

{{% details %}}
+ Environment Variable: None
+ Example: `48h`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: 720 hours (30 days)
+ Related: -
{{% /details %}}

Defines a default access token lifetime if the expiration was not defined by the authorization server.

The access token expiration is normally read from the refresh token, but if that lifetime is not positive, the configured `access-token-duration` will be used instead.

---

## `client-auth-method`

{{% details %}}
+ Environment Variable: `PROXY_CLIENT_AUTH_METHOD`
+ Example: `secret-basic` or `secret-body` (only 2 options)
+ Required: No
+ Default: `secret-basic`
+ Related: -
{{% /details %}}

Defines how gatekeeper will authenticate with the authorization server. TODO check if this is being used.

---

## `cookie-domain`

{{% details %}}
+ Environment Variable: None
+ Example: `foobar.org`
+ Required: No
+ Default: Uses the domain from the `Host` header
+ Related: -
{{% /details %}}

Defines the `Domain` attribute for the cookies stored on the browser.

Since the cookies contain the access and refresh token, this setting determines how much of your domain this sign-in covers.

For example, if `Domain` is set to `foobar.org`, when the user visits `foobar.org` or any of the subdomains `baz.foobar.org` or `quux.foobar.org`, the cookies will be sent to gatekeeper and the user will continue to be signed in.

See more information about setting the `Domain` attribute at [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Define_where_cookies_are_sent)

---

## `cookie-access-name`

{{% details %}}
+ Environment Variable: None
+ Example: `foobar` (any cookie name)
+ Required: No
+ Default: `kc-access`
+ Related: `cookie-refresh-name`
{{% /details %}}

Defines the name of the cookie that gatekeeper will use to store the access token.

---

## `cookie-refresh-name`

{{% details %}}
+ Environment Variable: None
+ Example: `foobar` (any cookie name)
+ Required: No
+ Default: `kc-state`
+ Related: `cookie-access-name`
{{% /details %}}

Defines the name of the cookie that gatekeeper will use to store the refresh token.

---

## `secure-cookie`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If true, gatekeeper will set the `Secure` attribute on the cookies used for access and refresh tokens.

If set, the cookies will only be sent to the server with an encrypted request over the HTTPS protocol: [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Restrict_access_to_cookies).

---

## `http-only-cookie`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

If true, gatekeeper will set the `HttpOnly` attribute on the cookies used for access and refresh tokens.

If set, the cookies will only be sent to the server; they will be inaccessible to the JavaScript `Document.cookie` API: [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Restrict_access_to_cookies:~:text=A%20cookie%20with%20the%20HttpOnly%20attribute%20is%20inaccessible%20to%20the%20JavaScript%20Document.cookie%20API).

---

## `same-site-cookie`

{{% details %}}
+ Environment Variable: None
+ Example: Three options: `Strict`, `Lax`, `None` (case-sensitive)
+ Required: No
+ Default: `Lax`
+ Related: -
{{% /details %}}

Gatekeeper uses this config option to set the `SameSite` attribute on the cookies used for access and refresh tokens.

See more at [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_attribute:~:text=SameSite%20attribute,-The)

---

## `match-claims`

{{% details %}}
+ Environment Variable: None
+ Example: `aud=myapp`, `iss=http://example.*`
+ Required: No
+ Default: No required claim matching
+ Related: -
{{% /details %}}

The proxy supports adding a variable list of claim matches against the
presented tokens for additional access control. You can match the `iss` or
`aud` to the token or custom attributes; each of the matches are regexes.

If `match-claims` is defined, the user's claims must match all of the requested
claims. You can configure this using the configuration file, like this:

``` yaml
match-claims:
  aud: openvpn
  iss: https://keycloak.example.com/auth/realms/commons
```

or via the CLI, like this:

``` bash
--match-claims=aud=openvpn --match-claims=iss=https://keycloak.example.com/realms/commons
```

The above definition means that the user's token must

+ contain both `aud` and `iss` claims AND
+ `aud` must match `openvpn`, and `iss` must match `https://keycloak.example.com/realms/commons`
    + so `foo_openvpn_bar` will match `openvpn`
    + use a tighter regex `^openvpn$` to match `openvpn` strictly

Another example: limitting the email domain permitted: if you want to limit to
only users on the `example.com` domain:

``` yaml
match-claims:
  email: ^.*@example.com$
```

The adapter supports matching on multi-value strings claims. The match
will succeed if ONE of the values matches, for example:

``` yaml
match-claims:
  perms: perm1
```

will successfully match

``` json
{
  "iss": "https://sso.example.com",
  "sub": "",
  "perms": ["perm1", "perm2"]
}
```

---

## `add-claims`

{{% details %}}
+ Environment Variable: None
+ Example: `email`, `email|Foo-Bar-Email`
+ Required: No
+ Default: No claims added as headers
+ Related: -
{{% /details %}}

Allows you to inject claims from the token as headers in the upstream request.

For example, to inject the user's `email`, specify

```yaml
add-claims:
  - email
```

If the token contains the `email` claim, the value of the claim will be
injected as the header `X-Auth-Email` in the upstream request.

The `X-Auth-` prefix is automatically added, and the header is also capitalized
and joined with dashes. Any symbols in this list: `_$><[].,+-/'%^&*()!\` will
be replaced by dashes (`-`).

```yaml
add-claims:
  - given_name
```

The above will inject `given_name` from the token as the `X-Auth-Given-Name`
header in the request going upstream.

To control the name of the header, use the pipe (`|`) character:

```yaml
add-claims:
  - `email|Foo-Bar-Email`
```

The above will inject `email` from the token as the `Foo-Bar-Email` header in
the request going upstream.

---

## `tls-cert`

{{% details %}}
+ Environment Variable: None
+ Example: `/path/to/tls/certificate`
+ Required: Required if `tls-private-key` is specified
+ Default: No TLS configured for gatekeeper
+ Related: `tls-private-key`
{{% /details %}}

`tls-cert` is the path to the PEM encoded certificate file. This certificate
file may contain intermediate certificates following the leaf certificate to
form a certificate chain.

This certificate is served to clients connecting to gatekeeper, for both
forward and reverse proxy mode.

This path is watched for changes and gatekeeper will pick up new certificate
files.

---

## `tls-private-key`

{{% details %}}
+ Environment Variable: None
+ Example: `/path/to/tls/private/key`
+ Required: Required if `tls-cert` is specified
+ Default: No TLS configured for gatekeeper
+ Related: `tls-cert`
{{% /details %}}

`tls-private-key` is the path to the PEM encoded private key file.

This private key should be the private key for `tls-cert`.

This path is watched for changes and gatekeeper will pick up new private key
files.

---

## `tls-ca-certificate`

{{% details %}}
+ Environment Variable: None
+ Example: `/path/to/tls/ca/certificate`
+ Required: Required if `tls-ca-key` is specified
+ Default: Will handle requests using self-signed certificate from elazarl/goproxy
+ Related: `tls-ca-key`
{{% /details %}}

`tls-ca-certificate` is the path to a PEM encoded certificate file. This allows
gatekeeper to sign a TLS certificate for itself, using this
`tls-ca-certificate` and `tls-ca-key`.

> TODO: verify if this CA cert/key only used for `CONNECT`?

This path is not watched for changes, unlike for `tls-private-key` and
`tls-cert`.

---

## `tls-ca-key`

{{% details %}}
+ Environment Variable: None
+ Example: `/path/to/tls/ca/key`
+ Required: Required if `tls-ca-certificate` is specified
+ Default: Will handle requests using self-signed certificate from elazarl/goproxy
+ Related: `tls-ca-certificate`
{{% /details %}}

`tls-ca-key` is the path to a PEM encoded private key file. This allows
gatekeeper to sign a TLS certificate for itself, using this
`tls-ca-certificate` and `tls-ca-key`.

This path is not watched for changes, unlike for `tls-private-key` and
`tls-cert`.

---

## `tls-client-certificate`

{{% details %}}
+ Environment Variable: None
+ Example: `/path/to/tls/client/certificate`
+ Required: No
+ Default: No client certificates used for upstream connections
+ Related: -
{{% /details %}}

If `tls-client-ceritificate` is provided, this certificate will be used for
upstream connections, for both forward and reverse proxy modes.

This path is not watched for changes, unlike for `tls-private-key` and
`tls-cert`.

---

## `skip-upstream-tls-verify`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: -
{{% /details %}}

Specify this to skip TLS verification for upstream requests.

If `true`, gatekeeper will not verify the upstream's certificate chain and host
name; gatekeeper will accept any certificate presented by the server and any
host name in that certificate.

---

## `cors-origins`

{{% details %}}
+ Environment Variable: None
+ Example: `https://example.com`
+ Required: No
+ Default: No CORS headers will be added
+ Related: `cors-methods`, `cors-headers`, `cors-exposed-headers`, `cors-credentials`, `cors-max-age`
{{% /details %}}

This is a list of origins that will be added to the `Access-Control-Allow-Origin` header.

---

## `cors-methods`

{{% details %}}
+ Environment Variable: None
+ Example: `GET`, `POST`
+ Required: No
+ Default: `["GET", "POST", "HEAD"]`
+ Related: `cors-origins`, `cors-headers`, `cors-exposed-headers`, `cors-credentials`, `cors-max-age`
{{% /details %}}

This is a list of methods that will be added to the `Access-Control-Allow-Methods` header.

> `cors-origins` has to be set before this configuration option takes effect

---

## `cors-headers`

{{% details %}}
+ Environment Variable: None
+ Example: `X-Foo-Bar`
+ Required: No
+ Default: `["Origin", "Accept", "Content-Type", "X-Requested-With"]`
+ Related: `cors-origins`, `cors-methods`, `cors-exposed-headers`, `cors-credentials`, `cors-max-age`
{{% /details %}}

This is a list of allowed headers that will be added to the `Access-Control-Allow-Headers` header.

`Origin` will always be appended to the requested list.

> `cors-origins` has to be set before this configuration option takes effect

---

## `cors-exposed-headers`

{{% details %}}
+ Environment Variable: None
+ Example: `X-Foo-Bar`
+ Required: No
+ Default: `[]`
+ Related: `cors-origins`, `cors-methods`, `cors-headers`, `cors-credentials`, `cors-max-age`
{{% /details %}}

This is a list of headers that will be added to the `Access-Control-Expose-Headers` header.

> `cors-origins` has to be set before this configuration option takes effect

---

## `cors-credentials`

{{% details %}}
+ Environment Variable: None
+ Example: `true`
+ Required: No
+ Default: `false`
+ Related: `cors-origins`, `cors-methods`, `cors-headers`, `cors-exposed-headers`, `cors-max-age`
{{% /details %}}

If set, gatekeeper will set the `Access-Control-Allow-Credentials` header with the value `true`.

> `cors-origins` has to be set before this configuration option takes effect

---

## `cors-max-age`

{{% details %}}
+ Environment Variable: None
+ Example: `600`
+ Required: No
+ Default: Use browser/client default
+ Related: `cors-origins`, `cors-methods`, `cors-headers`, `cors-exposed-headers`, `cors-credentials`
{{% /details %}}

This sets how long (in seconds) the results of a preflight request can be
cached for the request coming to gatekeeper. Sets the `Access-Control-Max-Age` header.

> `cors-origins` has to be set before this configuration option takes effect

---

## `hostnames`

{{% details %}}
+ Environment Variable: None
+ Example: `service.com`
+ Required: No
+ Default: `[]`
+ Related: `use-letsencrypt`, `enable-security-filter`
{{% /details %}}

If `hostnames` is set, gatekeeper will use this list of hostnames for the
security filter (if `enable-security-filter` is set) to only allow requests for
a hostname on this list of hostnames.

`hostnames` is also used with `use-letsencrypt`. If set, the certificate
manager will only request certificates for the hostnames on the list. This can
be left unspecified, but will result in a LetsEncrypt certificate being
requested for any hostname for which gatekeeper is run on and may result in the
gatekeeper reaching the CA's rate limit.

---

## `store-url`

{{% details %}}
+ Environment Variable: None
+ Example: `redis://127.0.0.1:6379`, `boltdb:///tmp/tokens"`
+ Required: No
+ Default: Use a cookie for the refresh token
+ Related: `encryption-key`
{{% /details %}}

This url must be a valid url. gatekeeper only supports redis and boltdb (bbolt)
for now.

If boltdb is used, the boltdb data snapshot file will be created at the
specified path.

This storage is used to store refresh tokens. If no storage is specified,
gatekeeper will store the refresh token, encrypted, in a cookie that is
returned to the client.

In all cases (redis, boltdb, or cookie), the refresh token is encrypted with
`encryption-key`.

---

## `encryption-key`

{{% details %}}
+ Environment Variable: `PROXY_ENCRYPTION_KEY`
+ Example: `yb96KrChmqnEOHuIbBi650T7VDqyTwLZ`
+ Required: Yes if `enable-refresh-tokens` is set
+ Default: None
+ Related: `encryption-key`
{{% /details %}}

`encryption-key` is used to encrypt the refresh token.

The `encryption-key` must be either 16 or 32 characters long. If it is 16
characters long, AES-128 will be selected. Otherwise, AES-256 will be selected.

---

## `no-redirects`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `true`, gatekeeper will just return a `401 Unauthorized` instead of
redirecting the user to the authorization server.

---

## `skip-token-verification`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `true`, gatekeeper will only verify expiration and roles, but skip all other
token verification steps.

---

## `skip-access-token-issuer-check`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `true`, gatekeeper will not check that `iss` in the access token matches the
issuer (Authorization server).

---

## `skip-access-token-clientid-check`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `client-id`
{{% /details %}}

If `true`, gatekeeper will not check that the configured `client-id` is among
the `aud` field of the access token.

---

## `upstream-keepalives`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `true`
+ Related: `upstream-keepalive-timeout`
{{% /details %}}

If `true` (the default), gatekeeper will use HTTP keep-alives when
communicating with the upstream.

---

## `upstream-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: -
{{% /details %}}

Maximum amount of time that gatekeeper will wait to connect to the upstream.

---

## `upstream-keepalive-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: `upstream-keepalives`
{{% /details %}}

The interval between keep-alive probes for an active network connection.

---

## `upstream-tls-handshake-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: -
{{% /details %}}

Maximum amount of time that gatekeeper will wait for a TLS handshake.

---

## `upstream-response-header-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: -
{{% /details %}}

Maximum amount of time that gatekeeper will wait for the upstream's response
headers after fully writing the request.

---

## `upstream-expect-continue-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: -
{{% /details %}}

Maximum amount of time that gatekeeper will wait for the upstream's first
response headers after fully writing the request headers if the request has an
"Expect: 100-continue" header.

---

## `verbose`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Set `verbose` to `true` to turn on debug/verbose logging.

---

## `enabled-proxy-protocol`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

Enables the `PROXY` protocol for gatekeeper, provided by
[proxyproto](https://github.com/pires/go-proxyproto). See more at
https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt

---

## `max-idle-connections`

{{% details %}}
+ Environment Variable: None
+ Example: `50`
+ Required: No
+ Default: `100`
+ Related: -
{{% /details %}}

Maximum number of idle upstream/keycloak connections that gatekeeper will keep
alive.

---

## `max-idle-connections-per-host`

{{% details %}}
+ Environment Variable: None
+ Example: `25`
+ Required: No
+ Default: `50`
+ Related: -
{{% /details %}}

Maximum number of idle upstream/keycloak connections that gatekeeper will keep
alive, per host. `max-idle-connections-per-host` must be a number > 0 and <=
`max-idle-connections`

---

## `server-read-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: `server-idle-timeout`
{{% /details %}}

This sets gatekeeper's maximum duration for reading the entire request from the
client, including the body.

---

## `server-write-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `10s`
+ Related: -
{{% /details %}}

This sets gatekeeper's maximum duration before timing out writes of the response.

---

## `server-idle-timeout`

{{% details %}}
+ Environment Variable: None
+ Example: `3s`, or `314ms`, (any string that can be parsed by [ParseDuration](https://golang.org/pkg/time/#ParseDuration)
+ Required: No
+ Default: `120s`
+ Related: `server-read-timeout`
{{% /details %}}

This sets the maximum time gatekeeper will wait for the next request when
keep-alives are enabled. If this is `0`, `server-read-timeout` is used. If
`server-read-timeout` is also `0`, there is no timeout.

---

## `use-letsencrypt`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: `letsencrypt-cache-dir`
{{% /details %}}

If `true`, gatekeeper will request a certificate from Let's Encrypt.

---

## `letsencrypt-cache-dir`

{{% details %}}
+ Environment Variable: None
+ Example: `/tmp/letsencrypt`
+ Required: No
+ Default: `./cache/`
+ Related: `use-letsencrypt`
{{% /details %}}

This path is used to store cached Let's Encrypt certificates.

---

## `sign-in-page`

{{% details %}}
+ Environment Variable: None
+ Example: `"templates/sign_in.html.tmpl"`
+ Required: No
+ Default: No custom sign in page
+ Related: `tags`
{{% /details %}}

By default, gatekeeper will immediately redirect users for
authentication. Specify `sign-in-page`, the path to a custom sign-in page
template, for gatekeeper will render this page and present it to the user. This
can be used as a landing page for your site, to guide users to sign in at the
authorization server.

The sign-in page will have a `redirect` variable passed into the scope, which
holds the OAuth redirection URL. Here's a sample custom sign-in page that you
can use.

``` html
<html>
<body>
<a href="{{ .redirect }}">Sign-in</a>
</body>
</html>
```

If you wish to pass additional variables into the templates, such as title,
sitename and so on, you can use the `--tags key=pair` option, like this:
`--tags title="This is my site"` and the variable would be accessible from `{{
.title }}`.

---

## `forbidden-page`

{{% details %}}
+ Environment Variable: None
+ Example: `"templates/forbidden.html.tmpl"`
+ Required: No
+ Default: No custom forbidden page
+ Related: `tags`
{{% /details %}}

If `forbidden-page` is specified, gatekeeper will render this page and present
it to the user when the user is not authorized to view some resource.

The format for interpolating tags is the same as the one used in
`sign-in-page`. `tags` will also be used to render the forbidden page.

---

## `tags`

{{% details %}}
+ Environment Variable: None
+ Example: `title=foobar`
+ Required: No
+ Default: No tags for custom page rendering.
+ Related: `sign-in-page`, `forbidden-page`
{{% /details %}}

The `tags` used when rendering the custom pages: `sign-in-page` and
`forbidden-page`.

---

## `forwarding-username`

{{% details %}}
+ Environment Variable: `PROXY_FORWARDING_USERNAME`
+ Example: `username`
+ Required: When gatekeeper is in forward proxy mode
+ Default: None
+ Related: `forwarding-password`
{{% /details %}}

This is the username used for logging in to the Authorization Server (OAuth2
Resource Owner Password Credentials flow) when gatekeeper is in forward proxy
mode.

---

## `forwarding-password`

{{% details %}}
+ Environment Variable: `PROXY_FORWARDING_PASSWORD`
+ Example: `password`
+ Required: When gatekeeper is in forward proxy mode
+ Default: None
+ Related: `forwarding-username`
{{% /details %}}

This is the password used for logging in to the Authorization Server (OAuth2
Resource Owner Password Credentials flow) when gatekeeper is in forward proxy
mode.

---

## `forwarding-domains`

{{% details %}}
+ Environment Variable: None
+ Example: `example.com`
+ Required: No
+ Default: Will add access token for any domains requested through gatekeeper.
+ Related: -
{{% /details %}}

If configured, gatekeeper will only add an access token (do authorization for)
to any request bound for any of the domains on this list. If not specified,
gatekeeper will do authorization for all domains.

Only used when gatekeeper is in forward proxy mode.

---

## `disable-all-logging`

{{% details %}}
+ Environment Variable: None
+ Example: `true` or `false`
+ Required: No
+ Default: `false`
+ Related: -
{{% /details %}}

If `true`, gatekeeper will not log to stdout or stderr.
