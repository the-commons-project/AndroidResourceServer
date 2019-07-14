package com.curiosityhealth.androidresourceserver.resourceserver.client

import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeRequest

interface ClientManager {
    fun client(clientId: String, completion: (Client?, Exception?) -> Unit)
    fun clearClientHandshake(clientId: String)
    fun getClientHandshake(clientId: String) : ClientHandshake?
    fun registerClientHandshake(clientId: String, clientHandshake: ClientHandshake)
    fun setApprovedScopes(clientId: String, approvedScopes: Set<ScopeRequest>)
    fun getApprovedScopes(clientId: String) : Set<ScopeRequest>?
    fun clearApprovedScopes(clientId: String)
}

sealed class ClientManagerException(s: String) : Exception(s) {
    class ClientNotFound(s: String): ClientManagerException(s)
}