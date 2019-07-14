package com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement

import android.content.Context
import com.curiosityhealth.androidresourceserver.common.Authorization.AllowedScope
import com.curiosityhealth.androidresourceserver.common.Authorization.Scope
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeAccess
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.resourceserver.client.Client
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientHandshake
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManagerException
import com.google.crypto.tink.JsonKeysetReader
import com.google.crypto.tink.JsonKeysetWriter
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.integration.android.AndroidKeystoreKmsClient
import org.researchsuite.researchsuiteextensions.common.RSKeyValueStore
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptedJavaObjectConverter
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptionManager
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptor
import java.io.ByteArrayOutputStream


class SampleClientManager(
    filePath: String,
    context: Context
) : ClientManager {

    class SampleScope(identifier: String, description: String) : Scope(identifier, description)

    companion object {

        private var _shared: SampleClientManager? = null
        public val shared: SampleClientManager
            get() = _shared!!

        fun configure(filePath: String, context: Context) {
            this._shared = SampleClientManager(filePath, context)
        }

        val SampleScope1 = SampleScope("sample_scope_1", "Sample Scope 1")
        val SampleScope2 = SampleScope("sample_scope_2", "Sample Scope 2")
        val SampleScope3 = SampleScope("sample_scope_3", "Sample Scope 3")

        //scopes should probably be defined at the local server level
        //permitted scopes on a per client basis should only refer to identifier + read/write
        val allowedScopes: Set<AllowedScope> = setOf(
            AllowedScope(
                SampleScope1,
                ScopeAccess.READ
            ),
            AllowedScope(
                SampleScope1,
                ScopeAccess.WRITE
            ),
            AllowedScope(
                SampleScope2,
                ScopeAccess.READ
            ),
            AllowedScope(
                SampleScope3,
                ScopeAccess.WRITE
            )
        )
    }

    val clientList = listOf<Client>(
        Client("sample_client_id", "Sample Client App", allowedScopes)
    )

    private val encryptionManager: RSEncryptionManager
    private val encryptor: RSEncryptor
    private val keyValueStore: RSKeyValueStore

    init {
        TinkConfig.register()

        this.encryptionManager = RSEncryptionManager(
            "SampleHandshakeClientRegistrationStorage.encryptionManager.masterKey",
            context,
            "SampleHandshakeClientRegistrationStorage.encryptionManager.prefsFile"
        )

        this.encryptor = encryptionManager.getAEADEncryptor("SampleHandshakeClientRegistrationStorage.kvs")

        this.keyValueStore = RSKeyValueStore(filePath, RSEncryptedJavaObjectConverter(encryptor))

    }

    private fun storeKeyset(keyName: String, keysetHandle: KeysetHandle) {
        val keysetHandleByteStream = ByteArrayOutputStream()
        keysetHandle.write(
            JsonKeysetWriter.withOutputStream(keysetHandleByteStream),
            AndroidKeystoreKmsClient().getAead(this.encryptionManager.masterKeyUri)
        )

        this.keyValueStore.set(keyName, keysetHandleByteStream.toByteArray())
    }

    private fun loadKeyset(keyName: String) : KeysetHandle? {
        val keysetHandleBytes: ByteArray = (this.keyValueStore.get(keyName) as? ByteArray)?: return null
        return KeysetHandle.read(
            JsonKeysetReader.withBytes(keysetHandleBytes),
            AndroidKeystoreKmsClient().getAead(this.encryptionManager.masterKeyUri)
        )
    }

    override fun client(clientId: String, completion: (Client?, Exception?) -> Unit) {

        val client: Client? = clientList.first { it.clientId == clientId }
        if (client == null) {
            completion(null, ClientManagerException.ClientNotFound("Client $clientId not found"))
        }
        else {
            completion(client, null)
        }

    }

    override fun clearClientHandshake(clientId: String) {
        val keys: List<String> = this.keyValueStore.currentMap?.keys?.filter { it.startsWith(clientId) } ?: emptyList()
        keys.forEach { this.keyValueStore.remove(it) }
    }

    override fun getClientHandshake(clientId: String): ClientHandshake? {

        val clientPublicSigningKey: KeysetHandle = this.loadKeyset("$clientId.clientPublicSigningKey") ?: return null
        val clientPublicEncryptionKey: KeysetHandle = this.loadKeyset("$clientId.clientPublicEncryptionKey") ?: return null
        val serverPrivateSigningKey: KeysetHandle = this.loadKeyset("$clientId.serverPrivateSigningKey") ?: return null
        val serverPrivateEncryptionKey: KeysetHandle = this.loadKeyset("$clientId.serverPrivateEncryptionKey") ?: return null

        return ClientHandshake(
            clientId,
            clientPublicSigningKey,
            clientPublicEncryptionKey,
            serverPrivateSigningKey,
            serverPrivateEncryptionKey
        )
    }

    override fun registerClientHandshake(clientId: String, clientHandshake: ClientHandshake) {
        this.storeKeyset("$clientId.clientPublicSigningKey", clientHandshake.clientPublicSigningKey)
        this.storeKeyset("$clientId.clientPublicEncryptionKey", clientHandshake.clientPublicEncryptionKey)
        this.storeKeyset("$clientId.serverPrivateSigningKey", clientHandshake.serverPrivateSigningKey)
        this.storeKeyset("$clientId.serverPrivateEncryptionKey", clientHandshake.serverPrivateEncryptionKey)
    }

    override fun setApprovedScopes(clientId: String, approvedScopes: Set<ScopeRequest>) {
        val key = "$clientId.approvedScopes"
        val scopeArray: List<String> = approvedScopes.map { it.toScopeRequestString() }
        this.keyValueStore.set(key, scopeArray)
    }

    override fun getApprovedScopes(clientId: String): Set<ScopeRequest>? {
        val key = "$clientId.approvedScopes"
        val scopeArray: List<String>? = this.keyValueStore.get(key) as? List<String>
        return scopeArray?.map { ScopeRequest.fromScopeRequestString(it) }?.toSet()
    }

    override fun clearApprovedScopes(clientId: String) {
        val key = "$clientId.approvedScopes"
        this.keyValueStore.remove(key)
    }
}