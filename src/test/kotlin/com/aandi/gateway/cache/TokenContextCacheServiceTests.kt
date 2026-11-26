package com.aandi.gateway.cache

import com.aandi.gateway.security.UserRole
import org.junit.jupiter.api.Test
import org.springframework.data.redis.RedisConnectionFailureException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import tools.jackson.databind.ObjectMapper
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.HexFormat
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TokenContextCacheServiceTests {

    private val objectMapper = ObjectMapper()
    private val redis = InMemoryTokenCacheRedis()
    private val ttl = Duration.ofMinutes(15)
    private val repository = TokenContextCacheRepository(redis.template, TokenCacheProperties(ttl))
    private val service = TokenContextCacheService(repository, TokenContextPayloadFactory(objectMapper))
    private val invalidationService = TokenContextInvalidationService(repository)

    @Test
    fun `cache miss builds payload and stores it with subject index`() {
        val authentication = jwtAuthentication(SUBJECT, UserRole.ORGANIZER, tokenValue = "access-token-1")

        val resolution = assertNotNull(service.resolve(authentication).block())

        assertFalse(resolution.cacheHit)
        val payload = objectMapper.readTree(resolution.payloadJson)
        assertEquals(SUBJECT, payload.get("subject").asString())
        assertEquals(listOf("ROLE_ORGANIZER", "ROLE_USER"), payload.get("roles").map { it.asString() })
        Instant.parse(payload.get("cachedAt").asString())

        val tokenKey = "cache:token:$SUBJECT:${sha256("access-token-1")}"
        val indexKey = "cache:token-index:$SUBJECT"
        assertEquals(resolution.payloadJson, redis.values[tokenKey])
        assertEquals<Set<String>?>(setOf(tokenKey), redis.sets[indexKey])
        assertEquals(ttl, redis.ttls[tokenKey])
        assertEquals(ttl, redis.ttls[indexKey])
    }

    @Test
    fun `cache hit returns stored payload without rewriting`() {
        val authentication = jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "access-token-1")
        val tokenKey = "cache:token:$SUBJECT:${sha256("access-token-1")}"
        redis.values[tokenKey] = """{"subject":"cached"}"""

        val resolution = assertNotNull(service.resolve(authentication).block())

        assertTrue(resolution.cacheHit)
        assertEquals("""{"subject":"cached"}""", resolution.payloadJson)
        assertTrue(redis.sets.isEmpty())
        assertTrue(redis.ttls.isEmpty())
    }

    @Test
    fun `second resolve for the same token is served from cache`() {
        val authentication = jwtAuthentication(SUBJECT, UserRole.ADMIN, tokenValue = "access-token-1")

        val first = assertNotNull(service.resolve(authentication).block())
        val second = assertNotNull(service.resolve(authentication).block())

        assertFalse(first.cacheHit)
        assertTrue(second.cacheHit)
        assertEquals(first.payloadJson, second.payloadJson)
    }

    @Test
    fun `different tokens of the same subject are cached separately under one index`() {
        service.resolve(jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "token-a")).block()
        service.resolve(jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "token-b")).block()

        assertEquals<Set<String>?>(
            setOf(
                "cache:token:$SUBJECT:${sha256("token-a")}",
                "cache:token:$SUBJECT:${sha256("token-b")}"
            ),
            redis.sets["cache:token-index:$SUBJECT"]
        )
    }

    @Test
    fun `redis failure falls back to freshly built payload`() {
        redis.failure = RedisConnectionFailureException("redis down")
        val authentication = jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "access-token-1")

        val resolution = assertNotNull(service.resolve(authentication).block())

        assertFalse(resolution.cacheHit)
        assertEquals(SUBJECT, objectMapper.readTree(resolution.payloadJson).get("subject").asString())
        assertTrue(redis.values.isEmpty())
    }

    @Test
    fun `non jwt authentication is cached by hashed principal name`() {
        val authentication = UsernamePasswordAuthenticationToken(
            "demo-user",
            "n/a",
            listOf(SimpleGrantedAuthority("ROLE_USER"))
        )

        val resolution = assertNotNull(service.resolve(authentication).block())

        val tokenKey = "cache:token:${sha256("demo-user")}"
        assertEquals(resolution.payloadJson, redis.values[tokenKey])
        assertEquals<Set<String>?>(setOf(tokenKey), redis.sets["cache:token-index:demo-user"])
        assertEquals("demo-user", objectMapper.readTree(resolution.payloadJson).get("subject").asString())
    }

    @Test
    fun `jwt without subject is indexed as unknown and payload uses authentication name`() {
        val jwt = Jwt.withTokenValue("token-without-sub")
            .header("alg", "HS256")
            .claim("role", "USER")
            .build()
        val authentication = JwtAuthenticationToken(jwt, UserRole.USER.grantedAuthorities(), "fallback-name")

        val resolution = assertNotNull(service.resolve(authentication).block())

        assertTrue(redis.values.containsKey("cache:token:unknown:${sha256("token-without-sub")}"))
        assertEquals("fallback-name", objectMapper.readTree(resolution.payloadJson).get("subject").asString())
    }

    @Test
    fun `logout invalidation evicts every cached token of the subject`() {
        service.resolve(jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "token-a")).block()
        service.resolve(jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "token-b")).block()
        service.resolve(jwtAuthentication(OTHER_SUBJECT, UserRole.USER, tokenValue = "token-c")).block()

        val evicted = invalidationService.invalidateOnLogout(SUBJECT).block()

        assertEquals(3L, evicted)
        assertEquals<Set<String>?>(setOf("cache:token:$OTHER_SUBJECT:${sha256("token-c")}"), redis.values.keys)
        assertEquals<Set<String>?>(setOf("cache:token-index:$OTHER_SUBJECT"), redis.sets.keys)

        val afterInvalidation = jwtAuthentication(SUBJECT, UserRole.ADMIN, tokenValue = "token-a")
        assertFalse(assertNotNull(service.resolve(afterInvalidation).block()).cacheHit)
    }

    @Test
    fun `role change invalidation returns zero when redis fails`() {
        service.resolve(jwtAuthentication(SUBJECT, UserRole.USER, tokenValue = "token-a")).block()
        redis.failure = RedisConnectionFailureException("redis down")

        assertEquals(0L, invalidationService.invalidateOnRoleChanged(SUBJECT).block())
    }

    private fun jwtAuthentication(subject: String, role: UserRole, tokenValue: String): JwtAuthenticationToken {
        val jwt = Jwt.withTokenValue(tokenValue)
            .header("alg", "HS256")
            .subject(subject)
            .claim("role", role.name)
            .build()
        return JwtAuthenticationToken(jwt, role.grantedAuthorities(), subject)
    }

    private fun sha256(value: String): String {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.toByteArray()))
    }

    companion object {
        private const val SUBJECT = "123e4567-e89b-12d3-a456-426614174000"
        private const val OTHER_SUBJECT = "223e4567-e89b-12d3-a456-426614174000"
    }
}
