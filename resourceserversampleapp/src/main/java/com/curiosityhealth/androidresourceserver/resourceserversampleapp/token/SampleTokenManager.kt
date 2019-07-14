package com.curiosityhealth.androidresourceserver.resourceserversampleapp.token

import android.content.Context
import com.curiosityhealth.androidresourceserver.resourceserver.token.BaseTokenManager
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.Random
import org.researchsuite.researchsuiteextensions.common.RSKeyValueStore
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptedJavaObjectConverter
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptionManager
import org.researchsuite.researchsuiteextensions.encryption.RSEncryptor

class SampleTokenManager(
    filePath: String,
    context: Context
) : BaseTokenManager() {

    companion object {
        private var _shared: SampleTokenManager? = null
        public val shared: SampleTokenManager
            get() = _shared!!

        fun configure(filePath: String, context: Context) {
            this._shared = SampleTokenManager(filePath, context)
        }

        val issuer: String = "SampleApp"
        val SECRET_KEY = "secret"
    }

    private val encryptionManager: RSEncryptionManager
    private val encryptor: RSEncryptor
    private val keyValueStore: RSKeyValueStore
    private var _secret: ByteArray

    init {
        TinkConfig.register()

        this.encryptionManager = RSEncryptionManager(
            "SampleTokenManager.encryptionManager.masterKey",
            context,
            "SampleTokenManager.encryptionManager.prefsFile"
        )

        this.encryptor = encryptionManager.getAEADEncryptor("SampleTokenManager.kvs")

        this.keyValueStore = RSKeyValueStore(filePath, RSEncryptedJavaObjectConverter(encryptor))

        val storedSecret: ByteArray? = this.keyValueStore.get(SECRET_KEY) as? ByteArray
        if (storedSecret != null) {
            this._secret = storedSecret
        }
        else {
            val secret = Random.randBytes(64)
            this.keyValueStore.set(SECRET_KEY, secret)
            this._secret = secret
        }
    }

    override val secret: ByteArray
        get() = _secret
    override val issuer: String
        get() = SampleTokenManager.issuer
}