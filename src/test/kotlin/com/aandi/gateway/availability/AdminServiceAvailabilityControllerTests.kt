package com.aandi.gateway.availability

import com.aandi.gateway.common.response.GatewayErrorCode
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AdminServiceAvailabilityControllerTests {

    private val redis = InMemoryAvailabilityRedis()
    private val availabilityService = BackendServiceAvailabilityService(
        BackendServiceAvailabilityRepository(redis.template)
    )
    private val webTestClient = WebTestClient
        .bindToController(AdminServiceAvailabilityController(availabilityService))
        .build()

    @Test
    fun `list returns current toggle snapshot for every service`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")

        webTestClient.get()
            .uri("/v2/admin/service-availability")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$.success").isEqualTo(true)
            .jsonPath("$.error").doesNotExist()
            .jsonPath("$.data.services.length()").isEqualTo(2)
            .jsonPath("$.data.services[0].service").isEqualTo("ONLINE_JUDGE")
            .jsonPath("$.data.services[0].enabled").isEqualTo(false)
            .jsonPath("$.data.services[1].service").isEqualTo("REPORT")
            .jsonPath("$.data.services[1].enabled").isEqualTo(true)
    }

    @Test
    fun `update disables service with case-insensitive identifier`() {
        webTestClient.put()
            .uri("/v2/admin/service-availability/{service}", "report")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("""{"enabled":false}""")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$.success").isEqualTo(true)
            .jsonPath("$.data.service").isEqualTo("REPORT")
            .jsonPath("$.data.enabled").isEqualTo(false)

        assertEquals("false", redis.stored(BackendService.REPORT))
        assertEquals(false, availabilityService.isEnabled(BackendService.REPORT).block())
    }

    @Test
    fun `update re-enables a disabled service`() {
        redis.store(BackendService.ONLINE_JUDGE, "false")

        webTestClient.put()
            .uri("/v2/admin/service-availability/{service}", "ONLINE_JUDGE")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("""{"enabled":true}""")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$.data.service").isEqualTo("ONLINE_JUDGE")
            .jsonPath("$.data.enabled").isEqualTo(true)

        assertEquals("true", redis.stored(BackendService.ONLINE_JUDGE))
    }

    @Test
    fun `update with unknown service returns 404 without writing`() {
        val errorCode = GatewayErrorCode.ENDPOINT_NOT_ALLOWLISTED

        webTestClient.put()
            .uri("/v2/admin/service-availability/{service}", "post")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("""{"enabled":false}""")
            .exchange()
            .expectStatus().isNotFound
            .expectBody()
            .jsonPath("$.success").isEqualTo(false)
            .jsonPath("$.error.code").isEqualTo(errorCode.code)
            .jsonPath("$.error.value").isEqualTo(errorCode.value)

        assertNull(redis.hashes[InMemoryAvailabilityRedis.HASH_KEY])
    }

    @Test
    fun `update without enabled flag returns 400 without writing`() {
        val errorCode = GatewayErrorCode.LOGIN_REQUEST_BODY_INVALID

        webTestClient.put()
            .uri("/v2/admin/service-availability/{service}", "REPORT")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("""{}""")
            .exchange()
            .expectStatus().isBadRequest
            .expectBody()
            .jsonPath("$.success").isEqualTo(false)
            .jsonPath("$.error.code").isEqualTo(errorCode.code)
            .jsonPath("$.error.value").isEqualTo(errorCode.value)

        assertNull(redis.stored(BackendService.REPORT))
    }
}
