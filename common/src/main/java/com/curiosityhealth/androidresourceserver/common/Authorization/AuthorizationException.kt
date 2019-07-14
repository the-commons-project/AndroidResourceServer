package com.curiosityhealth.androidresourceserver.common.Authorization

sealed class AuthorizationException(s: String) : Exception(s) {
    class MalformedRequest(s: String): AuthorizationException(s)
    class MalformedResponse(s: String): AuthorizationException(s)
    class UnknownClient(s: String): AuthorizationException(s)
    class AuthorizationFailed(s: String): AuthorizationException(s)
    class TokenError(s: String): AuthorizationException(s)
}