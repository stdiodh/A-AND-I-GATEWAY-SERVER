package com.aandi.gateway.availability

import com.aandi.gateway.common.response.GatewayErrorCode
import com.aandi.gateway.common.response.GatewayResponseWriter
import org.junit.jupiter.api.Test
import org.springframework.data.redis.RedisConnectionFailureException
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import tools.jackson.databind.ObjectMapper
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BackendServiceAvailabilityToggleFilterTests {

    private val redis = InMemoryAvailabilityRedis()
    private val filter = BackendServiceAvailabilityFilter(
        availabilityService = BackendServiceAvailabilityService(BackendServiceAvailabilityRepository(redis.template)),
        responseWriter = GatewayResponseWriter(ObjectMapper(), "https://*.aandi.dev")
    )

    @Test
    fun `disabled service request is rejected with 503 and chain is not invoked`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")
        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v2/submissions")
                .header("Origin", "https://app.aandi.dev")
                .build()
        )
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertFalse(chain.invoked)
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, exchange.response.statusCode)
        assertEquals(MediaType.APPLICATION_JSON, exchange.response.headers.contentType)
        assertEquals("https://app.aandi.dev", exchange.response.headers.getFirst("Access-Control-Allow-Origin"))
        val body = ObjectMapper().readTree(exchange.response.bodyAsString.block())
        val errorCode = GatewayErrorCode.SERVICE_TEMPORARILY_DISABLED
        assertFalse(body.get("success").asBoolean())
        assertEquals(errorCode.code, body.get("error").get("code").asInt())
        assertEquals(errorCode.value, body.get("error").get("value").asString())
    }

    @Test
    fun `disabling one service does not affect the other`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/report/me").build())
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertTrue(chain.invoked)
        assertNull(exchange.response.statusCode)
    }

    @Test
    fun `enabled service request passes through`() {
        redis.store(BackendService.REPORT, "true")
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/courses/abc").build())
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertTrue(chain.invoked)
    }

    @Test
    fun `preflight request bypasses availability toggle`() {
        redis.store(BackendService.REPORT, "false")
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.options("/v2/report").build())
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertTrue(chain.invoked)
        assertNull(exchange.response.statusCode)
    }

    @Test
    fun `unrelated path is not checked against redis`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")
        redis.store(BackendService.REPORT, "false")
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/auth/me").build())
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertTrue(chain.invoked)
        assertEquals(0, redis.reads)
    }

    @Test
    fun `redis failure fails open for backend service requests`() {
        redis.failure = RedisConnectionFailureException("redis down")
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v2/submissions/1").build())
        val chain = RecordingChain()

        filter.filter(exchange, chain).block()

        assertTrue(chain.invoked)
        assertNull(exchange.response.statusCode)
    }

    private class RecordingChain : WebFilterChain {
        var invoked = false

        override fun filter(exchange: org.springframework.web.server.ServerWebExchange): Mono<Void> {
            invoked = true
            return Mono.empty()
        }
    }
}
