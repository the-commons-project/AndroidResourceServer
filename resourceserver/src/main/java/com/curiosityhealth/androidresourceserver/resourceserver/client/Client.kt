package com.curiosityhealth.androidresourceserver.resourceserver.client

import com.curiosityhealth.androidresourceserver.common.Authorization.AllowedScope

//TODO: Add package, redirect, signing signature, potentially other fields
class Client(
    val clientId: String,
    val description: String,
    val allowedScopes: Set<AllowedScope>
)