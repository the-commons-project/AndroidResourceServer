package com.curiosityhealth.androidresourceserver.common.Authorization

import java.io.Serializable

data class AuthorizationRequest(
    val clientId: String,
    val scope: String,
    val state: String,
    val includeRefreshToken: Boolean
)

