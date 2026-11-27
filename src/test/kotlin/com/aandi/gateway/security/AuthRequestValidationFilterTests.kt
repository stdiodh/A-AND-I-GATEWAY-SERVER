package com.aandi.gateway.security

import com.aandi.gateway.common.response.GatewayErrorCode
import com.aandi.gateway.common.response.GatewayResponseWriter
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Test
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.util.unit.DataSize
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import tools.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthRequestValidationFilterTests {

    private val jwtPolicy = JwtPolicyProperties(secret = SECRET)

    @Test
    fun `valid login body is forwarded with replayable body`() {
        val body = """{"username":"demo","password":"pw-1234"}"""
        val chain = RecordingChain()

        filter().filter(post("/v2/auth/login", body), chain).block()

        assertTrue(chain.invoked)
        assertEquals(body, chain.forwardedBody)
    }

    @Test
    fun `login without password or with blank username is rejected`() {
        listOf(
            """{"username":"demo"}""",
            """{"username":"   ","password":"pw"}""",
            """{"username":"demo","password":""}""",
            ""
        ).forEach { body ->
            val exchange = post("/v1/auth/login", body)
            val chain = RecordingChain()

            filter().filter(exchange, chain).block()

            assertFalse(chain.invoked, "body $body should be rejected")
            assertError(exchange, GatewayErrorCode.LOGIN_REQUEST_BODY_INVALID)
        }
    }

    @Test
    fun `refresh without refresh token is rejected as required`() {
        val exchange = post("/v2/auth/refresh", """{"refreshToken":"  "}""")
        val chain = RecordingChain()

        filter().filter(exchange, chain).block()

        assertFalse(chain.invoked)
        assertError(exchange, GatewayErrorCode.REFRESH_TOKEN_REQUIRED)
    }

    @Test
    fun `signed refresh token passes prevalidation`() {
        val chain = RecordingChain()
        val body = """{"refreshToken":"${token("REFRESH")}"}"""

        filter().filter(post("/v2/auth/refresh", body), chain).block()

        assertTrue(chain.invoked)
        assertEquals(body, chain.forwardedBody)
    }

    @Test
    fun `access token submitted as refresh token is rejected`() {
        assertRefreshRejected(token("ACCESS"))
    }

    @Test
    fun `refresh token signed with another secret is rejected`() {
        assertRefreshRejected(token("REFRESH", secret = "another-secret-key-with-32-bytes-minimum!"))
    }

    @Test
    fun `refresh token without token type or malformed is rejected`() {
        assertRefreshRejected(token(null))
        assertRefreshRejected("not-a-jwt")
    }

    @Test
    fun `logout applies the same refresh token prevalidation`() {
        val rejected = post("/v1/auth/logout", """{"refreshToken":"${token("ACCESS")}"}""")
        filter().filter(rejected, RecordingChain()).block()
        assertError(rejected, GatewayErrorCode.REFRESH_TOKEN_INVALID)

        val accepted = RecordingChain()
        filter().filter(post("/v2/auth/logout", """{"refreshToken":"${token("REFRESH")}"}"""), accepted).block()
        assertTrue(accepted.invoked)
    }

    @Test
    fun `refresh token type prevalidation can be disabled`() {
        val chain = RecordingChain()

        filter(SecurityPolicyProperties(prevalidateRefreshTokenType = false))
            .filter(post("/v2/auth/refresh", """{"refreshToken":"opaque-token"}"""), chain)
            .block()

        assertTrue(chain.invoked)
    }

    @Test
    fun `oversized auth body is rejected before validation`() {
        val exchange = post("/v2/auth/login", """{"username":"demo","password":"${"x".repeat(64)}"}""")
        val chain = RecordingChain()

        filter(SecurityPolicyProperties(maxRequestBodySize = DataSize.ofBytes(32))).filter(exchange, chain).block()

        assertFalse(chain.invoked)
        assertError(exchange, GatewayErrorCode.REQUEST_BODY_TOO_LARGE)
    }

    @Test
    fun `non post and non auth requests are not inspected`() {
        val get = RecordingChain()
        filter().filter(
            MockServerWebExchange.from(MockServerHttpRequest.get("/v2/auth/login").build()),
            get
        ).block()
        assertTrue(get.invoked)

        val otherPath = RecordingChain()
        val exchange = post("/v2/posts", """{"title":"no credentials"}""")
        filter().filter(exchange, otherPath).block()
        assertTrue(otherPath.invoked)
        assertNull(exchange.response.statusCode)
    }

    private fun assertRefreshRejected(refreshToken: String) {
        val exchange = post("/v2/auth/refresh", """{"refreshToken":"$refreshToken"}""")
        val chain = RecordingChain()

        filter().filter(exchange, chain).block()

        assertFalse(chain.invoked, "refresh token $refreshToken should be rejected")
        assertError(exchange, GatewayErrorCode.REFRESH_TOKEN_INVALID)
    }

    private fun assertError(exchange: MockServerWebExchange, errorCode: GatewayErrorCode) {
        assertEquals(errorCode.httpStatus, exchange.response.statusCode)
        val body = ObjectMapper().readTree(exchange.response.bodyAsString.block())
        assertEquals(errorCode.code, body.get("error").get("code").asInt())
        assertEquals(errorCode.value, body.get("error").get("value").asString())
    }

    private fun filter(policy: SecurityPolicyProperties = SecurityPolicyProperties()) =
        AuthRequestValidationFilter(
            jwtPolicy = jwtPolicy,
            policy = policy,
            responseWriter = GatewayResponseWriter(ObjectMapper(), "https://*"),
            requestBodyCache = AuthRequestBodyCache(policy)
        )

    private fun post(path: String, body: String): MockServerWebExchange {
        return MockServerWebExchange.from(
            MockServerHttpRequest.post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
        )
    }

    private fun token(tokenType: String?, secret: String = SECRET): String {
        val claims = JWTClaimsSet.Builder()
            .subject("123e4567-e89b-12d3-a456-426614174000")
            .apply { tokenType?.let { claim("token_type", it) } }
            .build()
        return SignedJWT(JWSHeader(JWSAlgorithm.HS256), claims).apply {
            sign(MACSigner(secret.toByteArray(StandardCharsets.UTF_8)))
        }.serialize()
    }

    private class RecordingChain : WebFilterChain {
        var invoked = false
        var forwardedBody: String? = null

        override fun filter(exchange: ServerWebExchange): Mono<Void> {
            invoked = true
            return DataBufferUtils.join(exchange.request.body)
                .map { buffer ->
                    val bytes = ByteArray(buffer.readableByteCount())
                    buffer.read(bytes)
                    DataBufferUtils.release(buffer)
                    String(bytes, StandardCharsets.UTF_8)
                }
                .defaultIfEmpty("")
                .doOnNext { forwardedBody = it }
                .then()
        }
    }

    companion object {
        private const val SECRET = "test-secret-key-with-32-bytes-minimum!"
    }
}
