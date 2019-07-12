package com.curiosityhealth.androidresourceserver.common.Authorization

sealed class AuthorizationException(s: String) : Exception(s) {
    class MalformedRequest(s: String): AuthorizationException(s)
    class UnknownClient(s: String): AuthorizationException(s)
}