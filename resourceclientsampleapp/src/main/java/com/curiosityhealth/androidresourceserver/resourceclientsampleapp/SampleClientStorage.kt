package com.curiosityhealth.androidresourceserver.resourceclientsampleapp

import android.content.Context
import com.curiosityhealth.androidresourceserver.resourceclient.AuthorizationClient
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

class SampleClientStorage(
    filePath: String,
    context: Context
) : AuthorizationClient.AuthorizationClientStorage {

    companion object {
        private var _shared: SampleClientStorage? = null
        public val shared: SampleClientStorage
            get() = _shared!!

        fun configure(filePath: String, context: Context) {
            this._shared = SampleClientStorage(filePath, context)
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

    override fun getClientPrivateSigningKey(): KeysetHandle? {
        return this.loadKeyset("clientPrivateSigningKey")
    }

    override fun storeClientPrivateSigningKey(keysetHandle: KeysetHandle) {
        this.storeKeyset("clientPrivateSigningKey", keysetHandle)
    }

    override fun getClientPrivateEncryptionKey(): KeysetHandle? {
        return this.loadKeyset("clientPrivateEncryptionKey")
    }

    override fun storeClientPrivateEncryptionKey(keysetHandle: KeysetHandle) {
        this.storeKeyset("clientPrivateEncryptionKey", keysetHandle)
    }

    override fun getServerPublicSigningKey(): KeysetHandle? {
        return this.loadKeyset("serverPublicSigningKey")
    }

    override fun storeServerPublicSigningKey(keysetHandle: KeysetHandle) {
        this.storeKeyset("serverPublicSigningKey", keysetHandle)
    }

    override fun getServerPublicEncryptionKey(): KeysetHandle? {
        return this.loadKeyset("serverPublicEncryptionKey")
    }

    override fun storeServerPublicEncryptionKey(keysetHandle: KeysetHandle) {
        this.storeKeyset("serverPublicEncryptionKey", keysetHandle)
    }

    override var accessToken: String?
        get() = this.keyValueStore.get("accessToken") as? String
        set(value) { this.keyValueStore.set("accessToken", value) }

    override var refreshToken: String?
        get() = this.keyValueStore.get("refreshToken") as? String
        set(value) { this.keyValueStore.set("refreshToken", value) }

    override fun clear() {
        this.keyValueStore.clear()
    }
}