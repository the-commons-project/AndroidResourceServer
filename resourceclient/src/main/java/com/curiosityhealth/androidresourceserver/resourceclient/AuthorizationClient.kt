package com.curiosityhealth.androidresourceserver.resourceclient

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import androidx.core.app.JobIntentService
import com.curiosityhealth.androidresourceserver.common.*
import com.curiosityhealth.androidresourceserver.common.Authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeRequest
import com.google.crypto.tink.*
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.hybrid.HybridDecryptFactory
import com.google.crypto.tink.hybrid.HybridEncryptFactory
import com.google.crypto.tink.hybrid.HybridKeyTemplates
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.signature.SignatureKeyTemplates
import com.google.crypto.tink.subtle.Random
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.GeneralSecurityException


class AuthorizationClient(val context: Context, val config: AuthorizationClientConfig, val clientStorage: AuthorizationClientStorage) {

    interface AuthorizationClientStorage {
        @Throws(GeneralSecurityException::class)
        fun getClientPrivateSigningKey() : KeysetHandle?
        @Throws(GeneralSecurityException::class)
        fun storeClientPrivateSigningKey(keysetHandle: KeysetHandle)

        @Throws(GeneralSecurityException::class)
        fun getClientPrivateEncryptionKey() : KeysetHandle?
        @Throws(GeneralSecurityException::class)
        fun storeClientPrivateEncryptionKey(keysetHandle: KeysetHandle)

        @Throws(GeneralSecurityException::class)
        fun getServerPublicSigningKey() : KeysetHandle?
        @Throws(GeneralSecurityException::class)
        fun storeServerPublicSigningKey(keysetHandle: KeysetHandle)

        @Throws(GeneralSecurityException::class)
        fun getServerPublicEncryptionKey() : KeysetHandle?
        @Throws(GeneralSecurityException::class)
        fun storeServerPublicEncryptionKey(keysetHandle: KeysetHandle)

        fun clear()
    }

    init {
        TinkConfig.register()
    }

    private var clientSigningPrivateKeysetHandle: KeysetHandle? = null
    private var clientEncryptionPrivateKeysetHandle: KeysetHandle? = null
    private var m1Data: ByteArray? = null
    private var handshakeState: Long = -1

    //authorization
    private var authorizationState: Long = -1

    fun authorize(
        context: Context,
        requestedScopes: Set<ScopeRequest>,
        includeRefreshToken: Boolean,
        completion: (successful: Boolean, exception: Exception?) -> Unit) {

        this.checkHandshake { checkSuccessful, checkException ->
            if (checkSuccessful) {
                doAuthorization(
                    context,
                    requestedScopes,
                    includeRefreshToken,
                    completion
                )
            }
            else {
                doHandshake(context) { successful, exception ->

                    if (successful) {
                        doAuthorization(
                            context,
                            requestedScopes,
                            includeRefreshToken,
                            completion
                        )
                    }
                    else {
                        completion(false, exception)
                    }

                }
            }
        }

    }

    private fun doAuthorization(
        context: Context,
        requestedScopes: Set<ScopeRequest>,
        includeRefreshToken: Boolean,
        completion: (successful: Boolean, exception: Exception?) -> Unit
    ) {
        completion(true, null)

        val authorizationCallback = object : Authorization.ResponseReceiver.ResponseReceiverCallBack {
            override fun onSuccess(response: Authorization.Response) {
                TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
            }

            override fun onError(exception: Exception) {
                TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
            }
        }

        val state = kotlin.random.Random.nextLong()

        //json serizalize parameters and encrypt them with server public key

        this.authorizationState = state

        val request = Authorization.Request(
            this.config.clientId,
            state,
            requestedScopes,
            includeRefreshToken
        )

        val publicEncryptionKeysetHandle = this.clientStorage.getServerPublicEncryptionKey()
        val privateSigningKeysetHandle = this.clientStorage.getClientPrivateSigningKey()

        if (publicEncryptionKeysetHandle == null || privateSigningKeysetHandle == null) {
            completion(false, null)
            return
        }

        val receiver = Authorization.ResponseReceiver(Handler(context.mainLooper))
        receiver.callback = authorizationCallback

        val intent = Authorization.Request.requestIntent(
            config.serverPackage,
            config.authorizationServiceClass,
            request,
            receiver,
            publicEncryptionKeysetHandle,
            privateSigningKeysetHandle
        )

        context.sendBroadcast(intent)
    }

    private fun checkHandshake(completion: (successful: Boolean, exception: Exception?) -> Unit) {

        //potentially verify handshake here
        val verifyHandshakeCallback = object : VerifyHandshake.ResponseReceiver.ResponseReceiverCallBack {
            override fun onSuccess(response: VerifyHandshake.Response) {
                //validate response
                //using server public signing key, verify signature
                val serverPublicSigningKey = clientStorage.getServerPublicSigningKey()
                if (serverPublicSigningKey == null) {
                    clientStorage.clear()
                    completion(false, null)
                    return
                }

                val verifier = PublicKeyVerifyFactory.getPrimitive(serverPublicSigningKey)
                verifier.verify(response.signature, response.data)

                //using client private encryption key, decrypt data
                val clientPrivateEncryptionKey = clientStorage.getClientPrivateEncryptionKey()
                if (clientPrivateEncryptionKey == null) {
                    clientStorage.clear()
                    completion(false, null)
                    return
                }

                val hybridDecrypt = HybridDecryptFactory.getPrimitive(clientPrivateEncryptionKey)
                val decryptedData = hybridDecrypt.decrypt(response.encryptedData, response.contextInfo)

                //compare decrypted data to data
                if (!response.data.contentEquals(decryptedData)) {
                    clientStorage.clear()
                    completion(false, null)
                    return
                }

                completion(true, null)
            }

            override fun onError(exception: Exception) {
                //clear client info
                clientStorage.clear()
                completion(false, exception)
            }

        }

        //
        try {

            //generate new data and sign it using client private signing key
            val clientPrivateSigningKey = this.clientStorage.getClientPrivateSigningKey()
            if (clientPrivateSigningKey == null) {
                completion(false, null)
                return
            }

            val data = Random.randBytes(1024)
            val signer = PublicKeySignFactory.getPrimitive(clientPrivateSigningKey)
            val signature = signer.sign(data)

            //encrypt data using server public encryption key
            val serverPublicEncryptionKey = this.clientStorage.getServerPublicEncryptionKey()
            if (serverPublicEncryptionKey == null) {
                completion(false, null)
                return
            }

            val hybridEncrypt = HybridEncryptFactory.getPrimitive(serverPublicEncryptionKey)
            val contextInfo = Random.randBytes(64)
            val encryptedData = hybridEncrypt.encrypt(data, contextInfo)

            val request = VerifyHandshake.Request(
                this.config.clientId,
                data,
                signature,
                encryptedData,
                contextInfo
            )

            val receiver = VerifyHandshake.ResponseReceiver(Handler(context.mainLooper))
            receiver.callback = verifyHandshakeCallback

            val intent = VerifyHandshake.Request.requestIntent(
                config.serverPackage,
                config.handshakeServiceClass,
                request,
                receiver
            )

            context.sendBroadcast(intent)
        }
        catch (gse: GeneralSecurityException) {
            verifyHandshakeCallback.onError(gse)
            return
        }

    }



    private fun doHandshake(context: Context, completion: (successful: Boolean, exception: Exception?) -> Unit) {
        val authorizationClient = this

        val completeHandshakeCallback = object : CompleteHandshake.ResponseReceiver.ResponseReceiverCallBack {
            override fun onSuccess(response: CompleteHandshake.Response) {

                //extract important info and save
                //client private keys, server public keys
                completion(true, null)
            }

            override fun onError(exception: Exception) {
                clientStorage.clear()
                completion(false, exception)
            }
        }

        val beginHandshakeCallback = object : BeginHandshake.ResponseReceiver.ResponseReceiverCallBack {
            override fun onSuccess(response: BeginHandshake.Response) {
                //validate response
//                authorizationClient.validateResponse(response)
                //extract important info and save (i.e., public keys)
                //complete handshake
                authorizationClient.completeHandshake(context, response, completeHandshakeCallback)
            }

            override fun onError(exception: Exception) {
                completion(false, exception)
            }

        }

        authorizationClient.beginHandshake(context, beginHandshakeCallback)
    }

    private fun beginHandshake(context: Context, callback: BeginHandshake.ResponseReceiver.ResponseReceiverCallBack) {

        this.clientSigningPrivateKeysetHandle = null
        this.clientEncryptionPrivateKeysetHandle = null
        this.m1Data = null

        this.clientStorage.clear()

        try {

            val m1Data = Random.randBytes(1024)

            val clientSigningPrivateKeysetHandle = KeysetHandle.generateNew(
                SignatureKeyTemplates.ECDSA_P256
            )
            val clientSigningPublicKeysetHandle = clientSigningPrivateKeysetHandle.publicKeysetHandle
            val clientSigningPublicKeysetHandleByteStream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(
                clientSigningPublicKeysetHandle,
                JsonKeysetWriter.withOutputStream(clientSigningPublicKeysetHandleByteStream)
            )

            val clientEncryptionPrivateKeysetHandle = KeysetHandle.generateNew(
                HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
            )
            val clientEncryptionPublicKeysetHandle = clientEncryptionPrivateKeysetHandle.publicKeysetHandle
            val clientEncryptionPublicKeysetHandleByteStream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(
                clientEncryptionPublicKeysetHandle,
                JsonKeysetWriter.withOutputStream(clientEncryptionPublicKeysetHandleByteStream)
            )

            val signer = PublicKeySignFactory.getPrimitive(clientSigningPrivateKeysetHandle)
            val signature = signer.sign(m1Data)

            val receiver = BeginHandshake.ResponseReceiver(Handler(context.mainLooper))
            receiver.callback = callback

            val state = kotlin.random.Random.nextLong()
            this.handshakeState = state

            val request = BeginHandshake.Request(
                config.clientId,
                state,
                clientSigningPublicKeysetHandleByteStream.toByteArray(),
                clientEncryptionPublicKeysetHandleByteStream.toByteArray(),
                m1Data,
                signature
            )

            val intent = BeginHandshake.Request.requestIntent(
                config.serverPackage,
                config.handshakeServiceClass,
                request,
                receiver
            )

            this.clientSigningPrivateKeysetHandle = clientSigningPrivateKeysetHandle
            this.clientEncryptionPrivateKeysetHandle = clientEncryptionPrivateKeysetHandle
            this.m1Data = m1Data

            context.sendBroadcast(intent)
        }
        catch (gse: GeneralSecurityException) {
            callback.onError(gse)
            return
        }
        catch (ioe: IOException) {
            callback.onError(ioe)
            return
        }


    }

    private fun completeHandshake(context: Context, response: BeginHandshake.Response, callback: CompleteHandshake.ResponseReceiver.ResponseReceiverCallBack) {

        try {

            //validate encryption
            val clientSigningPrivateKeysetHandle = this.clientSigningPrivateKeysetHandle
            val clientEncryptionPrivateKeysetHandle = this.clientEncryptionPrivateKeysetHandle
            val m1Data = this.m1Data
            if (clientSigningPrivateKeysetHandle == null ||
                clientEncryptionPrivateKeysetHandle == null ||
                m1Data == null) {
                val exception = HandshakeException.InvalidState("Invalid client State")
                callback.onError(exception)
                return
            }

            val hybridDecrypt = HybridDecryptFactory.getPrimitive(clientEncryptionPrivateKeysetHandle)
            val decryptedM1Data = hybridDecrypt.decrypt(response.m1EncryptedData, response.contextInfo)
            assert(m1Data.contentEquals(decryptedM1Data))
            if (!m1Data.contentEquals(decryptedM1Data)) {
                val exception = HandshakeException.InvalidState("M1 data does not match")
                callback.onError(exception)
                return
            }

            //validate signature
            val serverSigningPublicKey = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(response.signingPublicKey))
            val verifier = PublicKeyVerifyFactory.getPrimitive(serverSigningPublicKey)
            verifier.verify(response.m2Signature, response.m2Data)

            //encrypt m2 w/ server public key
            val serverEncryptionPublicKey = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(response.encryptionPublicKey))

            val hybridEncrypt = HybridEncryptFactory.getPrimitive(serverEncryptionPublicKey)

            val contextInfo = Random.randBytes(64)

            val m2EncryptedData = hybridEncrypt.encrypt(response.m2Data, contextInfo)

            this.clientStorage.storeClientPrivateSigningKey(clientSigningPrivateKeysetHandle)
            this.clientStorage.storeClientPrivateEncryptionKey(clientEncryptionPrivateKeysetHandle)
            this.clientStorage.storeServerPublicSigningKey(serverSigningPublicKey)
            this.clientStorage.storeServerPublicEncryptionKey(serverEncryptionPublicKey)

            val request = CompleteHandshake.Request(
                config.clientId,
                this.handshakeState,
                m2EncryptedData,
                contextInfo
            )

            val receiver = CompleteHandshake.ResponseReceiver(Handler(context.mainLooper))
            receiver.callback = callback

            val intent = CompleteHandshake.Request.requestIntent(
                config.serverPackage,
                config.handshakeServiceClass,
                request,
                receiver
            )

            context.sendBroadcast(intent)

        }
        catch (gse: GeneralSecurityException) {
            callback.onError(gse)
            return
        }
        catch (ioe: IOException) {
            callback.onError(ioe)
            return
        }

    }

}