/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.server.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Resources;
import com.google.inject.Key;
import io.airlift.http.server.HttpServerConfig;
import io.airlift.http.server.HttpServerInfo;
import io.airlift.http.server.testing.TestingHttpServer;
import io.airlift.node.NodeInfo;
import io.airlift.security.pem.PemReader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.trino.plugin.base.security.AllowAllSystemAccessControl;
import io.trino.security.AccessControl;
import io.trino.security.AccessControlManager;
import io.trino.server.security.oauth2.OAuth2Client;
import io.trino.server.testing.TestingTrinoServer;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.BasicPrincipal;
import io.trino.spi.security.Identity;
import io.trino.spi.security.SystemSecurityContext;
import okhttp3.Credentials;
import okhttp3.Headers;
import okhttp3.JavaNetCookieJar;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.inject.Inject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;

import java.io.File;
import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivateKey;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.collect.Iterables.getOnlyElement;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.google.inject.multibindings.OptionalBinder.newOptionalBinder;
import static io.airlift.http.client.HttpUriBuilder.uriBuilderFrom;
import static io.airlift.jaxrs.JaxrsBinder.jaxrsBinder;
import static io.trino.client.OkHttpUtil.setupSsl;
import static io.trino.client.ProtocolHeaders.TRINO_HEADERS;
import static io.trino.server.HttpRequestSessionContext.extractAuthorizedIdentity;
import static io.trino.server.security.ResourceSecurity.AccessType.AUTHENTICATED_USER;
import static io.trino.server.security.oauth2.OAuth2Service.NONCE;
import static io.trino.server.security.oauth2.OAuth2Service.hashNonce;
import static io.trino.spi.security.AccessDeniedException.denyImpersonateUser;
import static io.trino.spi.security.AccessDeniedException.denyReadSystemInformationAccess;
import static io.trino.testing.assertions.Assert.assertEquals;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Instant.now;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MINUTES;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_SEE_OTHER;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static javax.ws.rs.core.HttpHeaders.LOCATION;
import static javax.ws.rs.core.HttpHeaders.SET_COOKIE;
import static javax.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class TestResourceSecurity
{
    private static final String LOCALHOST_KEYSTORE = Resources.getResource("cert/localhost.pem").getPath();
    private static final String ALLOWED_USER_MAPPING_PATTERN = "(.*)@allowed";
    private static final ImmutableMap<String, String> SECURE_PROPERTIES = ImmutableMap.<String, String>builder()
            .put("http-server.https.enabled", "true")
            .put("http-server.https.keystore.path", LOCALHOST_KEYSTORE)
            .put("http-server.https.keystore.key", "")
            .put("http-server.process-forwarded", "true")
            .put("http-server.authentication.insecure.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
            .build();
    private static final String TEST_USER = "test-user";
    private static final String TEST_USER_LOGIN = TEST_USER + "@allowed";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PASSWORD2 = "test-password-2";
    private static final String MANAGEMENT_USER = "management-user";
    private static final String MANAGEMENT_USER_LOGIN = MANAGEMENT_USER + "@allowed";
    private static final String MANAGEMENT_PASSWORD = "management-password";
    private static final String HMAC_KEY = Resources.getResource("hmac_key.txt").getPath();
    private static final PrivateKey JWK_PRIVATE_KEY;
    private static final ObjectMapper json = new ObjectMapper();

    static {
        try {
            JWK_PRIVATE_KEY = PemReader.loadPrivateKey(new File(Resources.getResource("jwk/jwk-rsa-private.pem").getPath()), Optional.empty());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private OkHttpClient client;
    private Path passwordConfigDummy;

    @BeforeClass
    public void setup()
            throws IOException
    {
        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .followRedirects(false);
        setupSsl(
                clientBuilder,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.of(LOCALHOST_KEYSTORE),
                Optional.empty(),
                Optional.empty());
        client = clientBuilder.build();

        passwordConfigDummy = Files.createTempFile("passwordConfigDummy", "");
        passwordConfigDummy.toFile().deleteOnExit();
    }

    @Test
    public void testInsecureAuthenticatorHttp()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .put("http-server.authentication.insecure.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertInsecureAuthentication(httpServerInfo.getHttpUri());
        }
    }

    @Test
    public void testInsecureAuthenticatorHttps()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(SECURE_PROPERTIES)
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertInsecureAuthentication(httpServerInfo.getHttpUri());
            assertInsecureAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testInsecureAuthenticatorHttpsOnly()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.allow-insecure-over-http", "false")
                        .build())
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertAuthenticationDisabled(httpServerInfo.getHttpUri());
            assertInsecureAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testPasswordAuthenticator()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertAuthenticationDisabled(httpServerInfo.getHttpUri());
            assertPasswordAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testMultiplePasswordAuthenticators()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate, TestResourceSecurity::authenticate2);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertAuthenticationDisabled(httpServerInfo.getHttpUri());
            assertPasswordAuthentication(httpServerInfo.getHttpsUri(), TEST_PASSWORD, TEST_PASSWORD2);
        }
    }

    @Test
    public void testMultiplePasswordAuthenticatorsMessages()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate, TestResourceSecurity::authenticate2);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            Request request = new Request.Builder()
                    .url(getAuthorizedUserLocation(httpServerInfo.getHttpsUri()))
                    .headers(Headers.of("Authorization", Credentials.basic(TEST_USER_LOGIN, "wrong_password")))
                    .build();
            try (Response response = client.newCall(request).execute()) {
                assertThat(response.message()).isEqualTo("Access Denied: Invalid credentials | Access Denied: Invalid credentials2");
            }
        }
    }

    @Test
    public void testPasswordAuthenticatorUserMapping()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .setAdditionalModule(binder -> jaxrsBinder(binder).bind(TestResource.class))
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));

            // Test sets basic auth user and X-Trino-User, and the authenticator is performing user mapping.
            // Normally this would result in an impersonation check to the X-Trino-User, but the password
            // authenticator has a hack to clear X-Trino-User in this case.
            Request request = new Request.Builder()
                    .url(getLocation(httpServerInfo.getHttpsUri(), "/username"))
                    .addHeader("Authorization", Credentials.basic(TEST_USER_LOGIN, TEST_PASSWORD))
                    .addHeader("X-Trino-User", TEST_USER_LOGIN)
                    .build();
            try (Response response = client.newCall(request).execute()) {
                assertEquals(response.code(), SC_OK);
                assertEquals(response.header("user"), TEST_USER);
            }
        }
    }

    @javax.ws.rs.Path("/username")
    public static class TestResource
    {
        private final AccessControl accessControl;

        @Inject
        public TestResource(AccessControl accessControl)
        {
            this.accessControl = accessControl;
        }

        @ResourceSecurity(AUTHENTICATED_USER)
        @GET
        public javax.ws.rs.core.Response echoToken(@Context HttpServletRequest servletRequest, @Context HttpHeaders httpHeaders)
        {
            Identity identity = extractAuthorizedIdentity(servletRequest, httpHeaders, Optional.empty(), accessControl, user -> ImmutableSet.of());
            return javax.ws.rs.core.Response.ok()
                    .header("user", identity.getUser())
                    .build();
        }
    }

    @Test
    public void testPasswordAuthenticatorWithInsecureHttp()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.allow-insecure-over-http", "true")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertInsecureAuthentication(httpServerInfo.getHttpUri());
            assertPasswordAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testFixedManagerAuthenticatorHttpInsecureEnabledOnly()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.allow-insecure-over-http", "true")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .put("management.user", MANAGEMENT_USER)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);

            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertFixedManagementUser(httpServerInfo.getHttpUri(), true);
            assertPasswordAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testFixedManagerAuthenticatorHttpInsecureDisabledOnly()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.allow-insecure-over-http", "false")
                        .put("http-server.authentication.password.user-mapping.pattern", ALLOWED_USER_MAPPING_PATTERN)
                        .put("management.user", MANAGEMENT_USER)
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);

            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertResponseCode(client, getPublicLocation(httpServerInfo.getHttpUri()), SC_OK);
            assertResponseCode(client, getAuthorizedUserLocation(httpServerInfo.getHttpUri()), SC_FORBIDDEN, TEST_USER_LOGIN, null);
            assertResponseCode(client, getManagementLocation(httpServerInfo.getHttpUri()), SC_OK);
            assertResponseCode(client, getManagementLocation(httpServerInfo.getHttpUri()), SC_OK, "unknown", "something");

            assertPasswordAuthentication(httpServerInfo.getHttpsUri());
        }
    }

    @Test
    public void testFixedManagerAuthenticatorHttps()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("password-authenticator.config-files", passwordConfigDummy.toString())
                        .put("http-server.authentication.type", "password")
                        .put("http-server.authentication.allow-insecure-over-http", "true")
                        .put("management.user", MANAGEMENT_USER)
                        .put("management.user.https-enabled", "true")
                        .build())
                .build()) {
            server.getInstance(Key.get(PasswordAuthenticatorManager.class)).setAuthenticators(TestResourceSecurity::authenticate);
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.WITH_IMPERSONATION);

            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));
            assertFixedManagementUser(httpServerInfo.getHttpUri(), true);
            assertFixedManagementUser(httpServerInfo.getHttpsUri(), false);
        }
    }

    @Test
    public void testCertAuthenticator()
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.type", "certificate")
                        .put("http-server.https.truststore.path", LOCALHOST_KEYSTORE)
                        .put("http-server.https.truststore.key", "")
                        .build())
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.NO_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));

            assertAuthenticationDisabled(httpServerInfo.getHttpUri());

            OkHttpClient.Builder clientBuilder = client.newBuilder();
            setupSsl(
                    clientBuilder,
                    Optional.of(LOCALHOST_KEYSTORE),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(LOCALHOST_KEYSTORE),
                    Optional.empty(),
                    Optional.empty());
            OkHttpClient clientWithCert = clientBuilder.build();
            assertAuthenticationAutomatic(httpServerInfo.getHttpsUri(), clientWithCert);
        }
    }

    @Test
    public void testJwtAuthenticator()
            throws Exception
    {
        verifyJwtAuthenticator(Optional.empty());
        verifyJwtAuthenticator(Optional.of("custom-principal"));
    }

    private void verifyJwtAuthenticator(Optional<String> principalField)
            throws Exception
    {
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.type", "jwt")
                        .put("http-server.authentication.jwt.key-file", HMAC_KEY)
                        .put("http-server.authentication.jwt.principal-field", principalField.orElse("sub"))
                        .build())
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.NO_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));

            assertAuthenticationDisabled(httpServerInfo.getHttpUri());

            String hmac = Files.readString(Paths.get(HMAC_KEY));
            JwtBuilder tokenBuilder = Jwts.builder()
                    .signWith(SignatureAlgorithm.HS256, hmac)
                    .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()));
            if (principalField.isPresent()) {
                tokenBuilder.claim(principalField.get(), "test-user");
            }
            else {
                tokenBuilder.setSubject("test-user");
            }
            String token = tokenBuilder.compact();

            OkHttpClient clientWithJwt = client.newBuilder()
                    .authenticator((route, response) -> response.request().newBuilder()
                            .header(AUTHORIZATION, "Bearer " + token)
                            .build())
                    .build();
            assertAuthenticationAutomatic(httpServerInfo.getHttpsUri(), clientWithJwt);
        }
    }

    @Test
    public void testJwtWithJwkAuthenticator()
            throws Exception
    {
        TestingHttpServer jwkServer = createTestingJwkServer();
        jwkServer.start();
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.type", "jwt")
                        .put("http-server.authentication.jwt.key-file", jwkServer.getBaseUrl().toString())
                        .build())
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.NO_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));

            assertAuthenticationDisabled(httpServerInfo.getHttpUri());

            String token = Jwts.builder()
                    .signWith(SignatureAlgorithm.RS256, JWK_PRIVATE_KEY)
                    .setHeaderParam(JwsHeader.KEY_ID, "test-rsa")
                    .setSubject("test-user")
                    .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()))
                    .compact();

            OkHttpClient clientWithJwt = client.newBuilder()
                    .authenticator((route, response) -> response.request().newBuilder()
                            .header(AUTHORIZATION, "Bearer " + token)
                            .build())
                    .build();
            assertAuthenticationAutomatic(httpServerInfo.getHttpsUri(), clientWithJwt);
        }
        finally {
            jwkServer.stop();
        }
    }

    @Test
    public void testOAuth2Authenticator()
            throws Exception
    {
        verifyOAuth2Authenticator(true, Optional.empty());
        verifyOAuth2Authenticator(false, Optional.empty());
        verifyOAuth2Authenticator(true, Optional.of("custom-principal"));
        verifyOAuth2Authenticator(false, Optional.of("custom-principal"));
    }

    private void verifyOAuth2Authenticator(boolean webUiEnabled, Optional<String> principalField)
            throws Exception
    {
        CookieManager cookieManager = new CookieManager();
        OkHttpClient client = this.client.newBuilder()
                .cookieJar(new JavaNetCookieJar(cookieManager))
                .build();

        String clientId = "client";
        Date tokenExpiration = Date.from(ZonedDateTime.now().plusMinutes(5).toInstant());
        String issuer = "http://example.com/";
        JwtBuilder accessTokenBuilder = Jwts.builder()
                .signWith(SignatureAlgorithm.RS256, JWK_PRIVATE_KEY)
                .setHeaderParam(JwsHeader.KEY_ID, "test-rsa")
                .setIssuer(issuer)
                .setAudience(clientId)
                .setExpiration(tokenExpiration);
        JwtBuilder idTokenBuilder = Jwts.builder()
                .signWith(SignatureAlgorithm.RS256, JWK_PRIVATE_KEY)
                .setHeaderParam(JwsHeader.KEY_ID, "test-rsa")
                .setIssuer(issuer)
                .setAudience(clientId)
                .setExpiration(tokenExpiration);
        if (principalField.isPresent()) {
            accessTokenBuilder.claim(principalField.get(), "test-user");
            idTokenBuilder.claim(principalField.get(), "test-user");
        }
        else {
            accessTokenBuilder.setSubject("test-user");
            idTokenBuilder.setSubject("test-user");
        }
        String accessToken = accessTokenBuilder.compact();

        TestingHttpServer jwkServer = createTestingJwkServer();
        jwkServer.start();
        try (TestingTrinoServer server = TestingTrinoServer.builder()
                .setProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.type", "oauth2")
                        .put("web-ui.enabled", String.valueOf(webUiEnabled))
                        .put("http-server.authentication.oauth2.issuer", issuer)
                        .put("http-server.authentication.oauth2.jwks-url", jwkServer.getBaseUrl().toString())
                        .put("http-server.authentication.oauth2.state-key", "test-state-key")
                        .put("http-server.authentication.oauth2.auth-url", issuer)
                        .put("http-server.authentication.oauth2.token-url", issuer)
                        .put("http-server.authentication.oauth2.client-id", clientId)
                        .put("http-server.authentication.oauth2.client-secret", "client-secret")
                        .put("http-server.authentication.oauth2.principal-field", principalField.orElse("sub"))
                        .build())
                .setAdditionalModule(binder -> newOptionalBinder(binder, OAuth2Client.class)
                        .setBinding()
                        .toInstance(new OAuth2Client()
                        {
                            @Override
                            public URI getAuthorizationUri(String state, URI callbackUri, Optional<String> nonceHash)
                            {
                                return URI.create("http://example.com/authorize?" + state);
                            }

                            @Override
                            public OAuth2Response getOAuth2Response(String code, URI callbackUri)
                            {
                                if (!"TEST_CODE".equals(code)) {
                                    throw new IllegalArgumentException("Expected TEST_CODE");
                                }
                                return new OAuth2Response(accessToken, Optional.of(now().plus(5, ChronoUnit.MINUTES)), Optional.of(idTokenBuilder.compact()));
                            }
                        }))
                .build()) {
            server.getInstance(Key.get(AccessControlManager.class)).addSystemAccessControl(TestSystemAccessControl.NO_IMPERSONATION);
            HttpServerInfo httpServerInfo = server.getInstance(Key.get(HttpServerInfo.class));

            assertAuthenticationDisabled(httpServerInfo.getHttpUri());

            // not logged in
            URI baseUri = httpServerInfo.getHttpsUri();
            assertOk(client, getPublicLocation(baseUri));
            OAuthBearer bearer = assertAuthenticateOAuth2Bearer(client, getAuthorizedUserLocation(baseUri), "http://example.com/authorize");
            assertAuthenticateOAuth2Bearer(client, getManagementLocation(baseUri), "http://example.com/authorize");
            assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN);

            // We must add the nonce to the ID token we will soon generate.
            idTokenBuilder.claim(NONCE, hashNonce(bearer.getNonceCookie().getValue()));
            // The second call to `assertAuthenticateOAuth2Bearer` above overwrites the nonce cookie we need.
            cookieManager.getCookieStore().add(cookieManager.getCookieStore().getURIs().get(0), bearer.getNonceCookie());
            // login with the callback endpoint
            assertOk(
                    client,
                    uriBuilderFrom(baseUri)
                            .replacePath("/oauth2/callback/")
                            .addParameter("code", "TEST_CODE")
                            .addParameter("state", bearer.getState())
                            .toString());
            assertEquals(getOauthToken(client, bearer.getTokenServer()), accessToken);

            // if Web UI is using oauth so we should get a cookie
            if (webUiEnabled) {
                HttpCookie cookie = getOnlyElement(cookieManager.getCookieStore().getCookies());
                assertEquals(cookie.getValue(), accessToken);
                assertEquals(cookie.getPath(), "/ui/");
                assertEquals(cookie.getDomain(), baseUri.getHost());
                assertTrue(cookie.getMaxAge() > 0 && cookie.getMaxAge() < MINUTES.toSeconds(5));
                assertTrue(cookie.isHttpOnly());
                cookieManager.getCookieStore().removeAll();
            }
            else {
                List<HttpCookie> cookies = cookieManager.getCookieStore().getCookies();
                assertTrue(cookies.isEmpty(), "Expected no cookies when webUi is not enabled, but got: " + cookies);
            }

            OkHttpClient clientWithOAuthToken = client.newBuilder()
                    .authenticator((route, response) -> response.request().newBuilder()
                            .header(AUTHORIZATION, "Bearer " + accessToken)
                            .build())
                    .build();
            assertAuthenticationAutomatic(httpServerInfo.getHttpsUri(), clientWithOAuthToken);
        }
        finally {
            jwkServer.stop();
        }
    }

    private static OAuthBearer assertAuthenticateOAuth2Bearer(OkHttpClient client, String url, String expectedRedirect)
            throws IOException
    {
        Request request = new Request.Builder()
                .url(url)
                .build();
        String redirectTo;
        String tokenServer;
        try (Response response = client.newCall(request).execute()) {
            assertEquals(response.code(), SC_UNAUTHORIZED, url);
            String authenticateHeader = response.header(WWW_AUTHENTICATE);
            assertNotNull(authenticateHeader);
            Pattern oauth2BearerPattern = Pattern.compile("Bearer x_redirect_server=\"(https://127.0.0.1:[0-9]+/oauth2/token/initiate/.+)\", x_token_server=\"(https://127.0.0.1:[0-9]+/oauth2/token/.+)\"");
            Matcher matcher = oauth2BearerPattern.matcher(authenticateHeader);
            assertTrue(matcher.matches(), format("Invalid authentication header.\nExpected: %s\nPattern: %s", authenticateHeader, oauth2BearerPattern));
            redirectTo = matcher.group(1);
            tokenServer = matcher.group(2);
        }

        request = new Request.Builder()
                .url(redirectTo)
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(response.code(), SC_SEE_OTHER);
            String locationHeader = response.header(LOCATION);
            assertNotNull(locationHeader);
            Pattern locationPattern = Pattern.compile(format("%s\\?(.+)", expectedRedirect));
            Matcher matcher = locationPattern.matcher(locationHeader);
            assertTrue(matcher.matches(), format("Invalid location header.\nExpected: %s\nPattern: %s", expectedRedirect, locationPattern));

            HttpCookie nonceCookie = HttpCookie.parse(requireNonNull(response.header(SET_COOKIE))).get(0);
            nonceCookie.setDomain(request.url().host());
            return new OAuthBearer(matcher.group(1), tokenServer, nonceCookie);
        }
    }

    private static class OAuthBearer
    {
        private final String state;
        private final String tokenServer;
        private final HttpCookie nonceCookie;

        public OAuthBearer(String state, String tokenServer, HttpCookie nonceCookie)
        {
            this.state = requireNonNull(state, "state is null");
            this.tokenServer = requireNonNull(tokenServer, "tokenServer is null");
            this.nonceCookie = requireNonNull(nonceCookie, "nonce is null");
        }

        public String getState()
        {
            return state;
        }

        public String getTokenServer()
        {
            return tokenServer;
        }

        public HttpCookie getNonceCookie()
        {
            return nonceCookie;
        }
    }

    private static String getOauthToken(OkHttpClient client, String url)
            throws IOException
    {
        Request request = new Request.Builder()
                .url(url)
                .build();
        try (Response response = client.newCall(request).execute()) {
            String body = requireNonNull(response.body()).string();
            return json.readValue(body, TokenDTO.class).token;
        }
    }

    private void assertInsecureAuthentication(URI baseUri)
            throws IOException
    {
        assertResponseCode(client, getManagementLocation(baseUri), SC_OK, MANAGEMENT_USER_LOGIN, null);
        // public
        assertOk(client, getPublicLocation(baseUri));
        // authorized user
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_OK, TEST_USER_LOGIN, null);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, "something");
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED, "unknown", null);
        // management
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED);
        assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, "something");
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, "unknown", null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_OK, MANAGEMENT_USER_LOGIN, null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, MANAGEMENT_USER_LOGIN, "something");
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, MANAGEMENT_USER_LOGIN, MANAGEMENT_PASSWORD);
        // internal
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN);
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, null);
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, MANAGEMENT_USER_LOGIN, null);
    }

    private void assertPasswordAuthentication(URI baseUri)
            throws IOException
    {
        assertPasswordAuthentication(baseUri, TEST_PASSWORD);
    }

    private void assertPasswordAuthentication(URI baseUri, String... allowedPasswords)
            throws IOException
    {
        // public
        assertOk(client, getPublicLocation(baseUri));
        // authorized user
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, null);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, "invalid");
        for (String password : allowedPasswords) {
            assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_OK, TEST_USER_LOGIN, password);
        }
        // management
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED);
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, TEST_USER_LOGIN, "invalid");
        for (String password : allowedPasswords) {
            assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, password);
        }
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, MANAGEMENT_USER_LOGIN, null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_UNAUTHORIZED, MANAGEMENT_USER_LOGIN, "invalid");
        assertResponseCode(client, getManagementLocation(baseUri), SC_OK, MANAGEMENT_USER_LOGIN, MANAGEMENT_PASSWORD);
        // internal
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN);
        for (String password : allowedPasswords) {
            assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, password);
        }
    }

    private static void assertAuthenticationAutomatic(URI baseUri, OkHttpClient authorizedClient)
            throws IOException
    {
        // public
        assertResponseCode(authorizedClient, getPublicLocation(baseUri), SC_OK);
        // authorized user
        assertResponseCode(authorizedClient, getAuthorizedUserLocation(baseUri), SC_OK);
        // management
        assertResponseCode(authorizedClient, getManagementLocation(baseUri), SC_FORBIDDEN);
        assertResponseCode(authorizedClient, getManagementLocation(baseUri), SC_OK, Headers.of(TRINO_HEADERS.requestUser(), MANAGEMENT_USER));
        // internal
        assertResponseCode(authorizedClient, getInternalLocation(baseUri), SC_FORBIDDEN);
    }

    private void assertAuthenticationDisabled(URI baseUri)
            throws IOException
    {
        // public
        assertOk(client, getPublicLocation(baseUri));
        // authorized user
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_FORBIDDEN);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_FORBIDDEN, "unknown", null);
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_FORBIDDEN, "unknown", "something");
        assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, TEST_PASSWORD);
        // management
        assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN);
        assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN, "unknown", null);
        assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN, "unknown", "something");
        assertResponseCode(client, getManagementLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, TEST_PASSWORD);
        // internal
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN);
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, "unknown", null);
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, "unknown", "something");
        assertResponseCode(client, getInternalLocation(baseUri), SC_FORBIDDEN, TEST_USER_LOGIN, TEST_PASSWORD);
    }

    private void assertFixedManagementUser(URI baseUri, boolean insecureAuthentication)
            throws IOException
    {
        assertResponseCode(client, getPublicLocation(baseUri), SC_OK);
        if (insecureAuthentication) {
            assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_OK, TEST_USER_LOGIN, null);
            assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_UNAUTHORIZED, "unknown", null);
        }
        else {
            assertResponseCode(client, getAuthorizedUserLocation(baseUri), SC_OK, TEST_USER_LOGIN, TEST_PASSWORD);
        }
        assertResponseCode(client, getManagementLocation(baseUri), SC_OK);
        assertResponseCode(client, getManagementLocation(baseUri), SC_OK, "unknown", "something");
    }

    private static void assertOk(OkHttpClient client, String url)
            throws IOException
    {
        assertResponseCode(client, url, SC_OK, null, null);
    }

    private static void assertResponseCode(OkHttpClient client, String url, int expectedCode)
            throws IOException
    {
        assertResponseCode(client, url, expectedCode, null, null);
    }

    private static void assertResponseCode(OkHttpClient client,
            String url,
            int expectedCode,
            String userName,
            String password)
            throws IOException
    {
        assertResponseCode(client, url, expectedCode, Headers.of("Authorization", Credentials.basic(firstNonNull(userName, ""), firstNonNull(password, ""))));
    }

    private static void assertResponseCode(OkHttpClient client,
            String url,
            int expectedCode,
            Headers headers)
            throws IOException
    {
        Request request = new Request.Builder()
                .url(url)
                .headers(headers)
                .build();
        try (Response response = client.newCall(request).execute()) {
            assertEquals(response.code(), expectedCode, url);
        }
    }

    private static String getInternalLocation(URI baseUri)
    {
        return getLocation(baseUri, "/v1/task");
    }

    private static String getManagementLocation(URI baseUri)
    {
        return getLocation(baseUri, "/v1/node");
    }

    private static String getAuthorizedUserLocation(URI baseUri)
    {
        return getLocation(baseUri, "/v1/query");
    }

    private static String getPublicLocation(URI baseUri)
    {
        return getLocation(baseUri, "/v1/info");
    }

    private static String getLocation(URI baseUri, String path)
    {
        return uriBuilderFrom(baseUri).replacePath(path).toString();
    }

    private static Principal authenticate(String user, String password)
    {
        if ((TEST_USER_LOGIN.equals(user) && TEST_PASSWORD.equals(password)) || (MANAGEMENT_USER_LOGIN.equals(user) && MANAGEMENT_PASSWORD.equals(password))) {
            return new BasicPrincipal(user);
        }
        throw new AccessDeniedException("Invalid credentials");
    }

    private static Principal authenticate2(String user, String password)
    {
        if ((TEST_USER_LOGIN.equals(user) && TEST_PASSWORD2.equals(password)) || (MANAGEMENT_USER_LOGIN.equals(user) && MANAGEMENT_PASSWORD.equals(password))) {
            return new BasicPrincipal(user);
        }
        throw new AccessDeniedException("Invalid credentials2");
    }

    private static class TestSystemAccessControl
            extends AllowAllSystemAccessControl
    {
        public static final TestSystemAccessControl WITH_IMPERSONATION = new TestSystemAccessControl(false);
        public static final TestSystemAccessControl NO_IMPERSONATION = new TestSystemAccessControl(true);

        private final boolean allowImpersonation;

        private TestSystemAccessControl(boolean allowImpersonation)
        {
            this.allowImpersonation = allowImpersonation;
        }

        @Override
        public void checkCanImpersonateUser(SystemSecurityContext context, String userName)
        {
            if (!allowImpersonation) {
                denyImpersonateUser(context.getIdentity().getUser(), userName);
            }
        }

        @Override
        public void checkCanReadSystemInformation(SystemSecurityContext context)
        {
            if (!context.getIdentity().getUser().equals(MANAGEMENT_USER)) {
                denyReadSystemInformationAccess();
            }
        }
    }

    private static TestingHttpServer createTestingJwkServer()
            throws IOException
    {
        NodeInfo nodeInfo = new NodeInfo("test");
        HttpServerConfig config = new HttpServerConfig().setHttpPort(0);
        HttpServerInfo httpServerInfo = new HttpServerInfo(config, nodeInfo);

        return new TestingHttpServer(httpServerInfo, nodeInfo, config, new JwkServlet(), ImmutableMap.of());
    }

    private static class JwkServlet
            extends HttpServlet
    {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException
        {
            String jwkKeys = Resources.toString(Resources.getResource("jwk/jwk-public.json"), UTF_8);
            response.getWriter().println(jwkKeys);
        }
    }

    private static class TokenDTO
    {
        @JsonProperty
        String token;
    }
}
