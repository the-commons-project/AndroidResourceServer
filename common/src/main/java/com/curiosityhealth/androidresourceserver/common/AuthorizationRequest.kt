package com.curiosityhealth.androidresourceserver.common

import java.io.Serializable

data class AuthorizationRequest(
    val responseType: AuthorizationResponseType,
    val clientId: String,
    val scope: String,
    val state: String,
    val includeRefreshToken: Boolean
) : Serializable

