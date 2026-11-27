package com.aandi.gateway.security

import com.aandi.gateway.common.response.GatewayResponseWriter
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.JwtValidationException
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import tools.jackson.databind.ObjectMapper
import java.time.Instant
import java.util.Date
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JwtDecoderValidationTests {

    private val policy = JwtPolicyProperties(
        issuer = ISSUER,
        audience = AUDIENCE,
        secret = SECRET,
        clockSkewSeconds = 30
    )
    private val decoder: ReactiveJwtDecoder = securityConfig().jwtDecoder(policy)

    @Test
    fun `valid signed access token is decoded with its claims`() {
        val jwt = decoder.decode(sign(claims())).block()

        assertEquals(SUBJECT, jwt?.subject)
        assertEquals("ADMIN", jwt?.getClaimAsString("role"))
        assertEquals(listOf(AUDIENCE, "report-service"), jwt?.audience)
    }

    @Test
    fun `token from another issuer is rejected`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(sign(claims { issuer("https://evil.example.com") })).block()
        }

        assertTrue(error.errors.any { it.description.orEmpty().contains("iss") }, "${error.errors}")
    }

    @Test
    fun `token without required audience is rejected`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(sign(claims { audience("report-service") })).block()
        }

        assertTrue(error.errors.any { it.description == "Missing required audience: $AUDIENCE" })
    }

    @Test
    fun `token expired beyond clock skew is rejected`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(
                sign(
                    claims {
                        issueTime(Date.from(Instant.now().minusSeconds(3600)))
                        expirationTime(Date.from(Instant.now().minusSeconds(120)))
                    }
                )
            ).block()
        }

        assertTrue(error.errors.any { it.description.orEmpty().contains("expired", ignoreCase = true) })
    }

    @Test
    fun `token expired within clock skew is still accepted`() {
        val jwt = decoder.decode(
            sign(
                claims {
                    issueTime(Date.from(Instant.now().minusSeconds(3600)))
                    expirationTime(Date.from(Instant.now().minusSeconds(5)))
                }
            )
        ).block()

        assertEquals(SUBJECT, jwt?.subject)
    }

    @Test
    fun `refresh token is rejected by access token claim validator`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(sign(claims { claim("token_type", "REFRESH") })).block()
        }

        assertTrue(error.errors.any { it.description == "token_type must be ACCESS" })
    }

    @Test
    fun `token with unknown role is rejected`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(sign(claims { claim("role", "SUPER_ADMIN") })).block()
        }

        assertTrue(error.errors.any { it.description == "role must be one of USER, ORGANIZER, ADMIN" })
    }

    @Test
    fun `token issued in the future beyond clock skew is rejected`() {
        val error = assertFailsWith<JwtValidationException> {
            decoder.decode(sign(claims { issueTime(Date.from(Instant.now().plusSeconds(300))) })).block()
        }

        assertTrue(error.errors.any { it.description == "iat cannot be in the future" })
    }

    @Test
    fun `token signed with a different secret is rejected`() {
        val error = assertFailsWith<BadJwtException> {
            decoder.decode(sign(claims(), secret = "another-secret-key-with-32-bytes-minimum!")).block()
        }

        assertFalse(error is JwtValidationException)
        val causeMessages = generateSequence<Throwable>(error) { it.cause }.mapNotNull { it.message }.toList()
        assertTrue(causeMessages.any { it.contains("Invalid signature") }, causeMessages.toString())
    }

    @Test
    fun `unsigned token is rejected`() {
        val unsigned = PlainJWT(claims()).serialize()

        val error = assertFailsWith<BadJwtException> {
            decoder.decode(unsigned).block()
        }

        assertFalse(error is JwtValidationException)
        assertTrue(error.message.orEmpty().contains("none"), error.message)
    }

    @Test
    fun `secret shorter than 32 bytes is refused at startup`() {
        val error = assertFailsWith<IllegalArgumentException> {
            securityConfig().jwtDecoder(policy.copy(secret = "too-short-secret"))
        }

        assertEquals("security.jwt.secret must be at least 32 bytes", error.message)
    }

    private fun securityConfig() = SecurityConfig(
        responseWriter = GatewayResponseWriter(ObjectMapper(), "https://*"),
        bearerTokenAuthenticationConverter = GatewayBearerTokenAuthenticationConverter()
    )

    private fun claims(customize: JWTClaimsSet.Builder.() -> Unit = {}): JWTClaimsSet {
        val now = Instant.now()
        return JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(listOf(AUDIENCE, "report-service"))
            .subject(SUBJECT)
            .jwtID("jti-1")
            .claim("token_type", "ACCESS")
            .claim("role", "ADMIN")
            .issueTime(Date.from(now.minusSeconds(10)))
            .expirationTime(Date.from(now.plusSeconds(600)))
            .apply(customize)
            .build()
    }

    private fun sign(claims: JWTClaimsSet, secret: String = SECRET): String {
        return SignedJWT(JWSHeader(JWSAlgorithm.HS256), claims).apply {
            sign(MACSigner(secret.toByteArray(Charsets.UTF_8)))
        }.serialize()
    }

    companion object {
        private const val ISSUER = "https://auth.aandi.test"
        private const val AUDIENCE = "aandi-gateway"
        private const val SECRET = "test-secret-key-with-32-bytes-minimum!"
        private const val SUBJECT = "123e4567-e89b-12d3-a456-426614174000"
    }
}
