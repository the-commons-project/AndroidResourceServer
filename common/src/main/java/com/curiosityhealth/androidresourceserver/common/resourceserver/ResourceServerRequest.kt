package com.curiosityhealth.androidresourceserver.common.resourceserver

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class ResourceServerRequest(
    val token: String?,
    val parametersJSON: String?
)
