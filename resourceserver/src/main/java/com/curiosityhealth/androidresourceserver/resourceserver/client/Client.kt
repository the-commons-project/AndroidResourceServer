package com.curiosityhealth.androidresourceserver.resourceserver.client

import com.curiosityhealth.androidresourceserver.common.AllowedScope

//TODO: Add package, redirect, signing signature, potentially other fields
class Client(
    val clientId: String,
    val allowedScopes: Set<AllowedScope>
)