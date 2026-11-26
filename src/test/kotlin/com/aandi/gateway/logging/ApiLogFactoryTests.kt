package com.aandi.gateway.logging

import com.aandi.gateway.common.response.GatewayErrorCode
import com.aandi.gateway.security.UserRole
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.reactive.HandlerMapping
import org.springframework.web.util.pattern.PathPatternParser
import tools.jackson.databind.ObjectMapper
import java.net.InetSocketAddress
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ApiLogFactoryTests {

    private val factory = ApiLogFactory(
        objectMapper = ObjectMapper(),
        properties = ApiLoggingProperties(
            env = "test",
            service = ApiLoggingProperties.ServiceProperties(name = "gateway")
        )
    )

    @Test
    fun `successful response is logged as INFO api log`() {
        val log = logFor(HttpStatus.OK, """{"success":true,"data":{"id":1}}""")

        assertEquals("INFO", log.level)
        assertEquals("API", log.logType)
        assertEquals("HTTP request completed", log.message)
        assertTrue(log.response.success)
        assertNull(log.response.error)
        assertEquals("success", log.tags[2])
    }

    @Test
    fun `2xx response carrying an error object is logged as failure`() {
        val log = logFor(
            HttpStatus.OK,
            """{"success":false,"data":null,"error":{"code":17001,"message":"downstream disabled"}}"""
        )

        assertEquals("WARN", log.level)
        assertEquals("API_ERROR", log.logType)
        assertEquals("downstream disabled", log.message)
        assertFalse(log.response.success)
        assertEquals(emptyMap<String, Any?>(), log.response.data)
        val error = assertNotNull(log.response.error)
        assertEquals(17001, error.code)
        assertEquals(GatewayErrorCode.SERVICE_TEMPORARILY_DISABLED.value, error.value)
        assertEquals(GatewayErrorCode.SERVICE_TEMPORARILY_DISABLED.alert, error.alert)
        assertEquals("fail", log.tags[2])
    }

    @Test
    fun `unknown downstream error code keeps code and fills status fallback fields`() {
        val log = logFor(HttpStatus.FORBIDDEN, """{"error":{"code":99999,"value":"CUSTOM"}}""")

        val error = assertNotNull(log.response.error)
        assertEquals(99999, error.code)
        assertEquals("CUSTOM", error.value)
        assertEquals(GatewayErrorCode.ACCESS_DENIED.message, error.message)
        assertEquals(GatewayErrorCode.ACCESS_DENIED.alert, error.alert)
        assertNull(log.response.data)
    }

    @Test
    fun `client error uses failure message from context and WARN level`() {
        val log = logFor(HttpStatus.BAD_REQUEST, "") { it.markFailure("validation failed: username") }

        assertEquals("WARN", log.level)
        assertEquals("validation failed: username", log.message)
        assertNull(log.response.data)
        assertFalse(log.response.success)
    }

    @Test
    fun `server error without body is logged as ERROR with failure message as error message`() {
        val log = logFor(HttpStatus.BAD_GATEWAY, "") { it.markFailure("ConnectException: refused") }

        assertEquals("ERROR", log.level)
        assertEquals("ConnectException: refused", log.message)
        assertEquals(502, log.http.statusCode)
        val error = assertNotNull(log.response.error)
        assertEquals(GatewayErrorCode.INTERNAL_SERVER_ERROR.code, error.code)
        assertEquals("ConnectException: refused", error.message)
    }

    @Test
    fun `server error without failure message falls back to error code message`() {
        val log = logFor(HttpStatus.INTERNAL_SERVER_ERROR, "")

        assertEquals("ERROR", log.level)
        assertEquals(GatewayErrorCode.INTERNAL_SERVER_ERROR.message, log.message)
    }

    @Test
    fun `unparsed and truncated successful bodies are summarized as metadata`() {
        val unparsed = logFor(HttpStatus.OK, "비밀 plain text")
        assertEquals(mapOf("unparsed" to true, "length" to "비밀 plain text".toByteArray().size), unparsed.response.data)
        assertTrue(unparsed.response.success)

        val truncated = logFor(HttpStatus.OK, TRUNCATED_BODY_MARKER)
        assertEquals(mapOf("truncated" to true), truncated.response.data)
    }

    @Test
    fun `request body is masked parsed or summarized`() {
        val json = logFor(HttpStatus.OK, "") {
            it.requestBody = """[{"password":"pw","items":[1,true,null]},"plain"]"""
        }
        assertEquals(
            listOf(mapOf("password" to "****", "items" to listOf(1, true, null)), "plain"),
            json.request.body
        )

        val truncated = logFor(HttpStatus.OK, "") { it.requestBody = TRUNCATED_BODY_MARKER }
        assertEquals(mapOf("truncated" to true), truncated.request.body)

        val unparsed = logFor(HttpStatus.OK, "") { it.requestBody = "username=demo&password=secret" }
        assertEquals(mapOf("unparsed" to true, "length" to 29), unparsed.request.body)
    }

    @Test
    fun `exception log records throwable summary and error code status`() {
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.delete("/v2/posts/9").build())
        val context = ApiLogContext.initialize(exchange)

        val log = factory.createExceptionLog(
            exchange,
            context,
            null,
            GatewayErrorCode.DOWNSTREAM_SERVICE_UNAVAILABLE,
            IllegalStateException("upstream reset")
        )

        assertEquals("ERROR", log.level)
        assertEquals("API_ERROR", log.logType)
        assertEquals("IllegalStateException: upstream reset", log.message)
        assertEquals("DELETE", log.http.method)
        assertEquals(GatewayErrorCode.DOWNSTREAM_SERVICE_UNAVAILABLE.httpStatus.value(), log.http.statusCode)
        assertFalse(log.response.success)
        assertEquals(GatewayErrorCode.DOWNSTREAM_SERVICE_UNAVAILABLE.code, log.response.error?.code)
        assertEquals(listOf("gateway", "posts", "fail", "posts"), log.tags)
    }

    @Test
    fun `exception without message uses error code message`() {
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/ping").build())
        val context = ApiLogContext.initialize(exchange)

        val log = factory.createExceptionLog(
            exchange,
            context,
            null,
            GatewayErrorCode.INTERNAL_SERVER_ERROR,
            RuntimeException()
        )

        assertEquals("RuntimeException: ${GatewayErrorCode.INTERNAL_SERVER_ERROR.message}", log.message)
    }

    @Test
    fun `anonymous and unauthenticated actors are not identified`() {
        val anonymous = logFor(HttpStatus.OK, "", authentication = null)
        assertEquals(ApiLogActor(userId = null, role = null, isAuthenticated = false), anonymous.actor)

        val unauthenticated = logFor(
            HttpStatus.OK,
            "",
            authentication = UsernamePasswordAuthenticationToken("15", "credentials")
        )
        assertEquals(ApiLogActor(userId = null, role = null, isAuthenticated = false), unauthenticated.actor)
    }

    @Test
    fun `jwt actor prefers userId claim and reports highest role`() {
        val log = logFor(HttpStatus.OK, "", authentication = jwtAuthentication("7", UserRole.ADMIN, userId = "42"))

        assertEquals(ApiLogActor(userId = 42, role = "ADMIN", isAuthenticated = true), log.actor)
    }

    @Test
    fun `jwt actor falls back to numeric subject then to unknown`() {
        val numericSubject = logFor(HttpStatus.OK, "", authentication = jwtAuthentication("7", UserRole.USER))
        assertEquals(7L, numericSubject.actor.userId)
        assertEquals("USER", numericSubject.actor.role)

        val uuidSubject = logFor(
            HttpStatus.OK,
            "",
            authentication = jwtAuthentication("123e4567-e89b-12d3-a456-426614174000", UserRole.ORGANIZER, userId = "abc")
        )
        assertNull(uuidSubject.actor.userId)
        assertEquals("ORGANIZER", uuidSubject.actor.role)
        assertTrue(uuidSubject.actor.isAuthenticated)
    }

    @Test
    fun `non jwt authenticated actor uses numeric principal name`() {
        val numeric = logFor(
            HttpStatus.OK,
            "",
            authentication = UsernamePasswordAuthenticationToken("15", "n/a", emptyList())
        )
        assertEquals(ApiLogActor(userId = 15, role = null, isAuthenticated = true), numeric.actor)

        val named = logFor(
            HttpStatus.OK,
            "",
            authentication = UsernamePasswordAuthenticationToken(
                "demo",
                "n/a",
                listOf(SimpleGrantedAuthority("ROLE_ORGANIZER"))
            )
        )
        assertEquals(ApiLogActor(userId = null, role = "ORGANIZER", isAuthenticated = true), named.actor)
    }

    @Test
    fun `client ip prefers first forwarded address over remote address`() {
        val forwarded = createLog(
            MockServerHttpRequest.get("/v2/ping")
                .header("X-Forwarded-For", " 203.0.113.5 , 10.0.0.1")
                .remoteAddress(InetSocketAddress("198.51.100.7", 4000))
        )
        assertEquals("203.0.113.5", forwarded.client.ip)

        val remote = createLog(
            MockServerHttpRequest.get("/v2/ping").remoteAddress(InetSocketAddress("198.51.100.7", 4000))
        )
        assertEquals("198.51.100.7", remote.client.ip)

        assertNull(createLog(MockServerHttpRequest.get("/v2/ping")).client.ip)
    }

    @Test
    fun `client and header metadata are captured with authenticate masked`() {
        val log = createLog(
            MockServerHttpRequest.get("/v2/ping")
                .header("X-Device-OS", "iOS")
                .header("Authorization", "Bearer raw-token")
                .header("User-Agent", "aandi-app/1.0")
                .header("App-Version", "1.2.3")
                .header("Salt", "salt-value")
        )

        assertEquals("iOS", log.headers.deviceOS)
        assertEquals("Bearer ****", log.headers.authenticate)
        assertEquals("salt-value", log.headers.salt)
        assertEquals("aandi-app/1.0", log.client.userAgent)
        assertEquals("1.2.3", log.client.appVersion)
    }

    @Test
    fun `route prefers handler best matching pattern over raw path`() {
        val pathPattern = createLog(MockServerHttpRequest.get("/v2/posts/9")) { exchange ->
            exchange.attributes[HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE] =
                PathPatternParser.defaultInstance.parse("/v2/posts/{postId}")
        }
        assertEquals("/v2/posts/{postId}", pathPattern.http.route)

        val stringPattern = createLog(MockServerHttpRequest.get("/v2/posts/9")) { exchange ->
            exchange.attributes[HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE] = "/v2/posts/*"
        }
        assertEquals("/v2/posts/*", stringPattern.http.route)

        assertEquals("/v2/posts/9", createLog(MockServerHttpRequest.get("/v2/posts/9")).http.route)
    }

    @Test
    fun `path variables and query parameters are masked by key`() {
        val log = createLog(
            MockServerHttpRequest.get("/v2/users/demo")
                .queryParam("token", "t1", "t2")
                .queryParam("page", "1")
        ) { exchange ->
            exchange.attributes[HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE] =
                mapOf("username" to "johndoe", "token" to "abc", "id" to "5")
        }

        assertEquals(mapOf("username" to "joh****", "token" to "****", "id" to "5"), log.request.pathVariables)
        assertEquals(listOf("****", "****"), log.request.query["token"])
        assertEquals("1", log.request.query["page"])
    }

    @Test
    fun `tags skip version and numeric segments`() {
        assertEquals(listOf("gateway", "root", "success", "root"), createLog(MockServerHttpRequest.get("/")).tags)
        assertEquals(
            listOf("gateway", "posts", "success", "comments"),
            createLog(MockServerHttpRequest.get("/v2/posts/123/comments")).tags
        )
        assertEquals(
            listOf("gateway", "users", "success", "users"),
            createLog(MockServerHttpRequest.get("/v1/users/42")).tags
        )
    }

    private fun logFor(
        status: HttpStatus,
        responseBody: String,
        authentication: Authentication? = null,
        customizeContext: (ApiLogContext) -> Unit = {}
    ): ApiStructuredLog {
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/test").build())
        exchange.response.statusCode = status
        val context = ApiLogContext.initialize(exchange)
        context.responseBody = responseBody
        customizeContext(context)
        return factory.create(exchange, context, authentication)
    }

    private fun createLog(
        request: MockServerHttpRequest.BaseBuilder<*>,
        customizeExchange: (MockServerWebExchange) -> Unit = {}
    ): ApiStructuredLog {
        val exchange = MockServerWebExchange.from(request.build())
        customizeExchange(exchange)
        return factory.create(exchange, ApiLogContext.initialize(exchange), null)
    }

    private fun jwtAuthentication(subject: String, role: UserRole, userId: String? = null): JwtAuthenticationToken {
        val builder = Jwt.withTokenValue("token")
            .header("alg", "HS256")
            .subject(subject)
            .claim("role", role.name)
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
        userId?.let { builder.claim("userId", it) }
        return JwtAuthenticationToken(builder.build(), role.grantedAuthorities(), subject)
    }
}
