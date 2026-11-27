package com.aandi.gateway.cache

import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.mockito.invocation.InvocationOnMock
import org.reactivestreams.Publisher
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.core.ReactiveSetOperations
import org.springframework.data.redis.core.ReactiveValueOperations
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Duration

/**
 * Mockito-backed Redis value/set store for token context cache tests.
 */
class InMemoryTokenCacheRedis {
    val values: MutableMap<String, String> = linkedMapOf()
    val sets: MutableMap<String, MutableSet<String>> = linkedMapOf()
    val ttls: MutableMap<String, Duration> = linkedMapOf()
    var failure: RuntimeException? = null

    private val valueOperations = mock(ReactiveValueOperations::class.java) { invocation ->
        failure?.let { return@mock error(invocation, it) }
        when (invocation.method.name) {
            "get" -> Mono.justOrEmpty(values[invocation.getArgument<String>(0)])
            "set" -> {
                val key = invocation.getArgument<String>(0)
                values[key] = invocation.getArgument(1)
                if (invocation.arguments.size == 3) {
                    ttls[key] = invocation.getArgument(2)
                }
                Mono.just(true)
            }
            else -> unsupported(invocation)
        }
    }

    private val setOperations = mock(ReactiveSetOperations::class.java) { invocation ->
        failure?.let { return@mock error(invocation, it) }
        when (invocation.method.name) {
            "add" -> {
                val members = invocation.rawArguments[1] as Array<*>
                val set = sets.getOrPut(invocation.getArgument(0)) { linkedSetOf() }
                Mono.just(members.count { set.add(it as String) }.toLong())
            }
            "members" -> Flux.fromIterable(sets[invocation.getArgument<String>(0)].orEmpty().toList())
            else -> unsupported(invocation)
        }
    }

    @Suppress("UNCHECKED_CAST")
    val template: ReactiveRedisTemplate<String, String> = mock(ReactiveRedisTemplate::class.java) { invocation ->
        when (invocation.method.name) {
            "opsForValue" -> valueOperations
            "opsForSet" -> setOperations
            "expire" -> failure?.let { Mono.error<Boolean>(it) } ?: run {
                ttls[invocation.getArgument(0)] = invocation.getArgument(1)
                Mono.just(true)
            }
            "delete" -> failure?.let { Mono.error<Long>(it) } ?: deleteKeys(invocation.getArgument(0))
            else -> unsupported(invocation)
        }
    } as ReactiveRedisTemplate<String, String>

    private fun error(invocation: InvocationOnMock, failure: RuntimeException): Publisher<*> {
        return if (Flux::class.java.isAssignableFrom(invocation.method.returnType)) {
            Flux.error<Any>(failure)
        } else {
            Mono.error<Any>(failure)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun deleteKeys(keys: Publisher<*>): Mono<Long> {
        return Flux.from(keys as Publisher<String>)
            .filter { key -> values.remove(key) != null || sets.remove(key) != null }
            .count()
    }

    private fun unsupported(invocation: InvocationOnMock): Any? {
        if (invocation.method.declaringClass == Any::class.java) {
            return Mockito.RETURNS_DEFAULTS.answer(invocation)
        }
        throw UnsupportedOperationException("Unexpected redis call: ${invocation.method}")
    }
}
