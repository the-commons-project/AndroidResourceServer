package com.curiosityhealth.androidresourceserver.resourceserver.client

import com.google.crypto.tink.KeysetHandle

data class ClientHandshake(
    val clientId: String,
    val clientPublicSigningKey: KeysetHandle,
    val clientPublicEncryptionKey: KeysetHandle,
    val serverPrivateSigningKey: KeysetHandle,
    val serverPrivateEncryptionKey: KeysetHandle
)