package com.curiosityhealth.androidresourceserver.resourceclient

data class AuthorizationClientConfig(
    val clientId: String,
    val serverPackage: String,
    val handshakeServiceClass: String,
    val authorizationServiceClass: String
)