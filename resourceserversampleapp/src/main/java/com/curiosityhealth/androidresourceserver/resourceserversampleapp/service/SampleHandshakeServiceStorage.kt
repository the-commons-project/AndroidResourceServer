package com.curiosityhealth.androidresourceserver.resourceserversampleapp.service

import android.content.Context
import com.curiosityhealth.androidresourceserver.resourceserver.service.HandshakeService
import com.google.crypto.tink.CleartextKeysetHandle
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
import java.lang.ref.WeakReference


//sample storage
//in production, you'd probably want to use an encrypted database
class SampleHandshakeServiceStorage(
    filePath: String,
    context: Context
) : HandshakeService.HandshakeServiceStorage {

    companion object {
        private var _shared: SampleHandshakeServiceStorage? = null
        public val shared: SampleHandshakeServiceStorage
            get() = _shared!!

        fun configure(filePath: String, context: Context) {
            this._shared = SampleHandshakeServiceStorage(filePath, context)
        }
    }

    private val encryptionManager: RSEncryptionManager
    private val encryptor: RSEncryptor
    private val keyValueStore: RSKeyValueStore

    init {
        TinkConfig.register()

        this.encryptionManager = RSEncryptionManager(
            "SampleHandshakeServiceStorage.encryptionManager.masterKey",
            context,
            "SampleHandshakeServiceStorage.encryptionManager.prefsFile"
        )

        this.encryptor = encryptionManager.getAEADEncryptor("SampleHandshakeServiceStorage.kvs")

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

    override fun getClientPublicSigningKey(clientId: String, state: Long): KeysetHandle? {
        val keyName = "$clientId.$state.clientPublicSigningKey"
        return loadKeyset(keyName)
    }

    override fun storeClientPublicSigningKey(keysetHandle: KeysetHandle, clientId: String, state: Long) {
        val keyName = "$clientId.$state.clientPublicSigningKey"
        this.storeKeyset(keyName, keysetHandle)
    }

    override fun getClientPublicEncryptionKey(clientId: String, state: Long): KeysetHandle? {
        val keyName = "$clientId.$state.clientPublicEncryptionKey"
        return loadKeyset(keyName)
    }

    override fun storeClientPublicEncryptionKey(keysetHandle: KeysetHandle, clientId: String, state: Long) {
        val keyName = "$clientId.$state.clientPublicEncryptionKey"
        this.storeKeyset(keyName, keysetHandle)
    }

    override fun getServerPrivateSigningKey(clientId: String, state: Long): KeysetHandle? {
        val keyName = "$clientId.$state.serverPrivateSigningKey"
        return loadKeyset(keyName)
    }

    override fun storeServerPrivateSigningKey(keysetHandle: KeysetHandle, clientId: String, state: Long) {
        val keyName = "$clientId.$state.serverPrivateSigningKey"
        this.storeKeyset(keyName, keysetHandle)
    }

    override fun getServerPrivateEncryptionKey(clientId: String, state: Long): KeysetHandle? {
        val keyName = "$clientId.$state.serverPrivateEncryptionKey"
        return loadKeyset(keyName)
    }

    override fun storeServerPrivateEncryptionKey(keysetHandle: KeysetHandle, clientId: String, state: Long) {
        val keyName = "$clientId.$state.serverPrivateEncryptionKey"
        this.storeKeyset(keyName, keysetHandle)
    }

    override fun getM2Data(clientId: String, state: Long): ByteArray? {
        val key = "$clientId.$state.m2Data"
        return this.keyValueStore.get(key) as? ByteArray
    }

    override fun storeM2Data(m2Data: ByteArray, clientId: String, state: Long) {
        val key = "$clientId.$state.m2Data"
        this.keyValueStore.set(key, m2Data)
    }

    override fun getState(clientId: String): Long? {
        val key = "$clientId.state"
        return this.keyValueStore.get(key) as? Long
    }

    override fun storeState(clientId: String, state: Long) {
        val key = "$clientId.state"
        this.keyValueStore.set(key, state)
    }

    override fun clear(clientId: String) {
        val keys: List<String> = this.keyValueStore.currentMap?.keys?.filter { it.startsWith(clientId) } ?: emptyList()
        keys.forEach { this.keyValueStore.remove(it) }
    }
}