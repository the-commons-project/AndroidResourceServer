package com.curiosityhealth.androidresourceserver.resourceserver.client

interface ClientManager {
    fun client(clientId: String, completion: (Client?, Exception?) -> Unit)
    fun clearClientHandshake(clientId: String)
    fun getClientHandshake(clientId: String) : ClientHandshake?
    fun registerClientHandshake(clientId: String, clientHandshake: ClientHandshake)
}

sealed class ClientManagerException(s: String) : Exception(s) {
    class ClientNotFound(s: String): ClientManagerException(s)
}