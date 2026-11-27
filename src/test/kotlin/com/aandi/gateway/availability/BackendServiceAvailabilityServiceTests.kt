package com.aandi.gateway.availability

import org.junit.jupiter.api.Test
import org.springframework.data.redis.RedisConnectionFailureException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BackendServiceAvailabilityServiceTests {

    private val redis = InMemoryAvailabilityRedis()
    private val service = BackendServiceAvailabilityService(BackendServiceAvailabilityRepository(redis.template))

    @Test
    fun `listAll returns every backend service in declaration order`() {
        redis.store(BackendService.REPORT, "false")

        val states = service.listAll().block()

        assertEquals(
            listOf(
                ServiceAvailabilityState(BackendService.ONLINE_JUDGE, true),
                ServiceAvailabilityState(BackendService.REPORT, false)
            ),
            states
        )
    }

    @Test
    fun `setEnabled persists toggle and returns resulting state`() {
        val state = service.setEnabled(BackendService.REPORT, false).block()

        assertEquals(ServiceAvailabilityState(BackendService.REPORT, false), state)
        assertEquals(false, service.isEnabled(BackendService.REPORT).block())
        assertEquals(true, service.isEnabled(BackendService.ONLINE_JUDGE).block())
    }

    @Test
    fun `setEnabled propagates redis write failure`() {
        redis.failure = RedisConnectionFailureException("redis down")

        assertFailsWith<RedisConnectionFailureException> {
            service.setEnabled(BackendService.REPORT, false).block()
        }
    }
}
