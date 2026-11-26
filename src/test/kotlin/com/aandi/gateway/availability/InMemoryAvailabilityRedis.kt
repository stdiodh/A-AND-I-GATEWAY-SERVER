package com.aandi.gateway.availability

import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.data.redis.core.ReactiveHashOperations
import org.springframework.data.redis.core.ReactiveRedisTemplate
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.util.AbstractMap
import java.util.concurrent.ConcurrentHashMap

/**
 * Mockito-backed Redis hash store used to exercise availability toggles without a Redis server.
 */
class InMemoryAvailabilityRedis {
    val hashes: MutableMap<String, MutableMap<String, String>> = ConcurrentHashMap()
    var failure: RuntimeException? = null
    var reads: Int = 0
        private set

    @Suppress("UNCHECKED_CAST")
    val template: ReactiveRedisTemplate<String, String> =
        mock(ReactiveRedisTemplate::class.java) as ReactiveRedisTemplate<String, String>

    @Suppress("UNCHECKED_CAST")
    private val hashOperations: ReactiveHashOperations<String, String, String> =
        mock(ReactiveHashOperations::class.java) as ReactiveHashOperations<String, String, String>

    init {
        `when`(template.opsForHash<String, String>()).thenReturn(hashOperations)
        `when`(hashOperations.get(anyString(), any())).thenAnswer { invocation ->
            reads++
            failure?.let { return@thenAnswer Mono.error<String>(it) }
            Mono.justOrEmpty(hashes[invocation.getArgument<String>(0)]?.get(invocation.getArgument<Any>(1)))
        }
        `when`(hashOperations.entries(anyString())).thenAnswer { invocation ->
            reads++
            failure?.let { return@thenAnswer Flux.error<Map.Entry<String, String>>(it) }
            Flux.fromIterable(
                hashes[invocation.getArgument<String>(0)].orEmpty().map { (field, value) ->
                    AbstractMap.SimpleImmutableEntry(field, value)
                }
            )
        }
        `when`(hashOperations.put(anyString(), anyString(), anyString())).thenAnswer { invocation ->
            failure?.let { return@thenAnswer Mono.error<Boolean>(it) }
            val key = invocation.getArgument<String>(0)
            val field = invocation.getArgument<String>(1)
            val previous = hashes.getOrPut(key) { ConcurrentHashMap() }.put(field, invocation.getArgument(2))
            Mono.just(previous == null)
        }
    }

    fun stored(service: BackendService): String? = hashes[HASH_KEY]?.get(service.name)

    fun store(service: BackendService, value: String) {
        hashes.getOrPut(HASH_KEY) { ConcurrentHashMap() }[service.name] = value
    }

    companion object {
        const val HASH_KEY = "gateway:service-availability"
    }
}
