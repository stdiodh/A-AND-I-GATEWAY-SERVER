package com.aandi.gateway.availability

import org.junit.jupiter.api.Test
import org.springframework.data.redis.RedisConnectionFailureException
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BackendServiceAvailabilityRepositoryTests {

    private val redis = InMemoryAvailabilityRedis()
    private val repository = BackendServiceAvailabilityRepository(redis.template)

    @Test
    fun `service without stored toggle is enabled by default`() {
        assertEquals(true, repository.isEnabled(BackendService.ONLINE_JUDGE).block())
    }

    @Test
    fun `stored toggle value is parsed case-insensitively`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")
        redis.store(BackendService.REPORT, "TRUE")

        assertEquals(false, repository.isEnabled(BackendService.ONLINE_JUDGE).block())
        assertEquals(true, repository.isEnabled(BackendService.REPORT).block())
    }

    @Test
    fun `unrecognized stored value is treated as disabled`() {
        redis.store(BackendService.REPORT, "yes")

        assertEquals(false, repository.isEnabled(BackendService.REPORT).block())
    }

    @Test
    fun `redis failure keeps service enabled`() {
        redis.store(BackendService.REPORT, "false")
        redis.failure = RedisConnectionFailureException("redis down")

        assertEquals(true, repository.isEnabled(BackendService.REPORT).block())
    }

    @Test
    fun `snapshot fills missing services with enabled and ignores unknown fields`() {
        redis.store(BackendService.REPORT, "false")
        redis.hashes.getValue(InMemoryAvailabilityRedis.HASH_KEY)["POST"] = "false"

        val snapshot = repository.snapshot().block()

        assertEquals(
            mapOf(BackendService.ONLINE_JUDGE to true, BackendService.REPORT to false),
            snapshot
        )
    }

    @Test
    fun `snapshot falls back to all enabled when redis fails`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")
        redis.failure = RedisConnectionFailureException("redis down")

        val snapshot = repository.snapshot().block()

        assertEquals(BackendService.entries.associateWith { true }, snapshot)
    }

    @Test
    fun `setEnabled writes string flag under service name`() {
        repository.setEnabled(BackendService.ONLINE_JUDGE, false).block()
        assertEquals("false", redis.stored(BackendService.ONLINE_JUDGE))
        assertFalse(repository.isEnabled(BackendService.ONLINE_JUDGE).block()!!)

        repository.setEnabled(BackendService.ONLINE_JUDGE, true).block()
        assertEquals("true", redis.stored(BackendService.ONLINE_JUDGE))
        assertTrue(repository.isEnabled(BackendService.ONLINE_JUDGE).block()!!)
    }
}
