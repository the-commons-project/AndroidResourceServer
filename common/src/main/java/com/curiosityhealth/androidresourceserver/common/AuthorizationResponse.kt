package com.curiosityhealth.androidresourceserver.common

import java.io.Serializable

enum class AuthorizationResponseType: Serializable {
    TOKEN
}

data class AuthorizationResponse(
    val accessToken: String,
    val refreshToken: String?,
    val state: String,
    val scope: String
)