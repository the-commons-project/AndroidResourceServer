package com.curiosityhealth.androidresourceserver.common

open class Scope(
    val identifier: String,
    val description: String
) {
    override fun equals(other: Any?): Boolean {
        val otherScope: Scope = (other as? Scope) ?: return false
        return otherScope.identifier == this.identifier &&
                otherScope.description == this.description
    }
}

class ScopeAccessException(s: String) : Exception(s)
class ScopeRequestException(s: String) : Exception(s)

enum class ScopeAccess {
    READ, WRITE;

    companion object {
        @Throws(ScopeAccessException::class)
        fun fromAccessString(accessString: String) : ScopeAccess {
            return when (accessString) {
                "read" -> READ
                "write" -> WRITE
                else -> throw ScopeAccessException("Invalid access: $accessString")
            }
        }
    }

    fun toAccessString() : String {
        return when (this) {
            READ -> "read"
            WRITE -> "write"
        }
    }
}

data class AllowedScope(
    val scope: Scope,
    val access: ScopeAccess
) {
    fun toScopeRequest() : ScopeRequest {
        return ScopeRequest(
            scope.identifier,
            access
        )
    }
}

data class ScopeRequest(
    val identifier: String,
    val access: ScopeAccess
) {
    companion object {
        @Throws(ScopeAccessException::class, ScopeRequestException::class)
        fun fromScopeRequestString(scopeRequestString: String) : ScopeRequest {
            val components = scopeRequestString.split(".")
            if (components.count() != 2) {
                throw ScopeRequestException("Invalid scope: $scopeRequestString")
            }

            return ScopeRequest(
                components[0],
                ScopeAccess.fromAccessString(components[1])
            )

        }
    }

    fun scopeRequestString() : String {
        return "${this.identifier}.${this.access.toAccessString()}"
    }
}



