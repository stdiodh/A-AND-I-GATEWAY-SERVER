package com.aandi.gateway.security

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserRoleTests {

    @Test
    fun `fromClaim resolves roles case-insensitively after trimming`() {
        assertEquals(UserRole.USER, UserRole.fromClaim("USER"))
        assertEquals(UserRole.ORGANIZER, UserRole.fromClaim("organizer"))
        assertEquals(UserRole.ADMIN, UserRole.fromClaim("  Admin "))
    }

    @Test
    fun `fromClaim rejects blank and unknown values`() {
        assertNull(UserRole.fromClaim(null))
        assertNull(UserRole.fromClaim(""))
        assertNull(UserRole.fromClaim("   "))
        assertNull(UserRole.fromClaim("ROLE_ADMIN"))
        assertNull(UserRole.fromClaim("SUPERUSER"))
    }

    @Test
    fun `granted authorities follow role hierarchy`() {
        assertEquals(listOf("ROLE_USER"), UserRole.USER.authorityNames())
        assertEquals(listOf("ROLE_ORGANIZER", "ROLE_USER"), UserRole.ORGANIZER.authorityNames())
        assertEquals(
            listOf("ROLE_ADMIN", "ROLE_ORGANIZER", "ROLE_USER"),
            UserRole.ADMIN.authorityNames()
        )
    }

    private fun UserRole.authorityNames(): List<String?> = grantedAuthorities().map { it.authority }
}
