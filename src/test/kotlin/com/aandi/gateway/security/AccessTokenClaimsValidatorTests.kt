package com.aandi.gateway.security

import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AccessTokenClaimsValidatorTests {

    private val now = Instant.parse("2026-01-01T00:00:00Z")
    private val validator = AccessTokenClaimsValidator(
        clockSkew = Duration.ofSeconds(30),
        clock = Clock.fixed(now, ZoneOffset.UTC)
    )

    @Test
    fun `access token with all required claims is accepted for every role`() {
        listOf("USER", "ORGANIZER", "ADMIN").forEach { role ->
            val result = validator.validate(jwt(role = role))

            assertTrue(result.errors.isEmpty(), "role $role should be accepted")
        }
    }

    @Test
    fun `role claim is matched case-insensitively after trimming`() {
        assertAccepted(validator.validate(jwt(role = " admin ")))
        assertAccepted(validator.validate(jwt(role = "Organizer")))
    }

    @Test
    fun `token type other than ACCESS is rejected`() {
        listOf(null, "REFRESH", "access", "").forEach { tokenType ->
            assertRejected(validator.validate(jwt(tokenType = tokenType)), "token_type must be ACCESS")
        }
    }

    @Test
    fun `subject that is missing or not a UUID is rejected`() {
        listOf(null, "", "user-1", "12345", "123e4567-e89b-12d3-a456").forEach { subject ->
            assertRejected(validator.validate(jwt(subject = subject)), "sub must be UUID")
        }
    }

    @Test
    fun `missing blank or unknown role is rejected`() {
        listOf(null, "", "   ", "SUPER_ADMIN", "ROLE_ADMIN", "GUEST").forEach { role ->
            assertRejected(
                validator.validate(jwt(role = role)),
                "role must be one of USER, ORGANIZER, ADMIN"
            )
        }
    }

    @Test
    fun `missing or blank jti is rejected`() {
        listOf(null, "", "  ").forEach { jti ->
            assertRejected(validator.validate(jwt(jti = jti)), "jti is required")
        }
    }

    @Test
    fun `missing issued at is rejected`() {
        assertRejected(validator.validate(jwt(issuedAt = null)), "iat is required")
    }

    @Test
    fun `issued at in the future beyond clock skew is rejected`() {
        assertRejected(
            validator.validate(jwt(issuedAt = now.plusSeconds(31))),
            "iat cannot be in the future"
        )
    }

    @Test
    fun `issued at within clock skew boundary is accepted`() {
        assertAccepted(validator.validate(jwt(issuedAt = now.plusSeconds(30))))
        assertAccepted(validator.validate(jwt(issuedAt = now.minusSeconds(3600))))
    }

    @Test
    fun `token type is checked before other claims`() {
        val result = validator.validate(
            jwt(tokenType = "REFRESH", subject = "not-uuid", role = "GUEST", jti = null)
        )

        assertEquals(1, result.errors.size)
        assertRejected(result, "token_type must be ACCESS")
    }

    private fun assertAccepted(result: OAuth2TokenValidatorResult) {
        assertTrue(result.errors.isEmpty(), "expected success but got ${result.errors}")
    }

    private fun assertRejected(result: OAuth2TokenValidatorResult, description: String) {
        val error = result.errors.singleOrNull()
        assertEquals("invalid_token", error?.errorCode)
        assertEquals(description, error?.description)
    }

    private fun jwt(
        tokenType: String? = "ACCESS",
        subject: String? = "123e4567-e89b-12d3-a456-426614174000",
        role: String? = "USER",
        jti: String? = "jti-1",
        issuedAt: Instant? = now.minusSeconds(10)
    ): Jwt {
        val builder = Jwt.withTokenValue("token")
            .header("alg", "HS256")
            .claim("iss", "http://localhost:9000")
            .expiresAt(now.plusSeconds(3600))
        tokenType?.let { builder.claim("token_type", it) }
        subject?.let { builder.subject(it) }
        role?.let { builder.claim("role", it) }
        jti?.let { builder.jti(it) }
        issuedAt?.let { builder.issuedAt(it) }
        return builder.build()
    }
}
