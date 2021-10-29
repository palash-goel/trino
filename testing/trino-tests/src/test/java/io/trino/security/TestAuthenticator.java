package io.trino.security;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Resources;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.trino.Session;
import io.trino.connector.MockConnectorFactory;
import io.trino.connector.MockConnectorPlugin;
import io.trino.plugin.blackhole.BlackHolePlugin;
import io.trino.plugin.tpch.TpchPlugin;
import io.trino.spi.security.RoleGrant;
import io.trino.spi.security.TrinoPrincipal;
import io.trino.testing.AbstractTestQueryFramework;
import io.trino.testing.DistributedQueryRunner;
import io.trino.testing.QueryRunner;
import okhttp3.OkHttpClient;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Optional;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static io.trino.client.OkHttpUtil.setupSsl;
import static io.trino.spi.security.PrincipalType.USER;
import static io.trino.testing.TestingSession.testSessionBuilder;
import static java.lang.String.format;

public class TestAuthenticator extends AbstractTestQueryFramework
{
    private static final String LOCALHOST_KEYSTORE = Resources.getResource("cert/localhost.pem").getPath();
    private static final ImmutableMap<String, String> SECURE_PROPERTIES = ImmutableMap.<String, String>builder()
            .put("http-server.https.enabled", "true")
            .put("http-server.https.keystore.path", LOCALHOST_KEYSTORE)
            .put("http-server.https.keystore.key", "")
            .put("http-server.process-forwarded", "true")
            .build();
    private static final String HMAC_KEY = Resources.getResource("hmac_key.txt").getPath();

    @Override
    protected QueryRunner createQueryRunner()
            throws Exception
    {
        Session session = testSessionBuilder()
                .setCatalog("blackhole")
                .setSchema("default")
                .build();
        DistributedQueryRunner queryRunner = DistributedQueryRunner.builder(session)
                .setExtraProperties(ImmutableMap.<String, String>builder()
                        .putAll(SECURE_PROPERTIES)
                        .put("http-server.authentication.type", "jwt")
                        .put("http-server.authentication.jwt.key-file", HMAC_KEY)
                        .put("http-server.authentication.jwt.principal-field", "sub")
                        .build())
                .setNodeCount(1)
                .build();

        String hmac = Files.readString(Paths.get(HMAC_KEY));
        JwtBuilder tokenBuilder = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, hmac)
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()));
        tokenBuilder.setSubject("test-user");
        String token = tokenBuilder.compact();


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
        OkHttpClient clientWithJwt = clientBuilder.build().newBuilder()
                .authenticator((route, response) -> response.request().newBuilder()
                        .header(AUTHORIZATION, "Bearer " + token)
                        .build())
                .build();

        queryRunner.installPlugin(new BlackHolePlugin());
        queryRunner.createCatalog("blackhole", "blackhole");
        queryRunner.installPlugin(new TpchPlugin());
        queryRunner.createCatalog("tpch", "tpch");
        queryRunner.installPlugin(new MockConnectorPlugin(MockConnectorFactory.builder()
                .withListRoleGrants((connectorSession, roles, grantees, limit) -> ImmutableSet.of(new RoleGrant(new TrinoPrincipal(USER, "alice"), "alice_role", false)))
                .build()));
        queryRunner.createCatalog("mock", "mock");
        for (String tableName : ImmutableList.of("orders", "nation", "region", "lineitem")) {
            queryRunner.execute(format("CREATE TABLE %1$s AS SELECT * FROM tpch.tiny.%1$s WITH NO DATA", tableName));
        }
        return queryRunner;
    }
}
