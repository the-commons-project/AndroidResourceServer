package com.curiosityhealth.androidresourceserver.resourceclient

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import androidx.core.app.JobIntentService
import com.curiosityhealth.androidresourceserver.common.*
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


class AuthorizationClient(val context: Context, val config: AuthorizationClientConfig) {

    init {
        TinkConfig.register()
    }

    private var clientSigningPrivateKeysetHandle: KeysetHandle? = null
    private var clientEncryptionPrivateKeysetHandle: KeysetHandle? = null
    private var m1Data: ByteArray? = null
    private var state: Long = -1

    fun doHandshake(context: Context, completion: (successful: Boolean, exception: Exception?) -> Unit) {
        val authorizationClient = this

        val completeHandshakeCallback = object : CompleteHandshake.ResponseReceiver.ResponseReceiverCallBack {
            override fun onSuccess(response: CompleteHandshake.Response) {

                //extract important info and save
                //client private keys, server public keys
                completion(true, null)
            }

            override fun onError(exception: Exception) {
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
            this.state = state

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

//            JobIntentService.enqueueWork(
//                context,
//                intent.component!!,
//                0,
//                intent
//            )

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

            val request = CompleteHandshake.Request(
                config.clientId,
                this.state,
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

//    fun getBeginHandshakeRequestIntent(): Intent? {
//
//        val intent = Intent()
//        intent.component = ComponentName(
//            config.serverPackage,
//            config.handshakeServiceClass
//        )
//
//        val randomBytes = Random.randBytes(1024)
//
//        // 1. Generate the private key material.
//        val signPrivateKeysetHandle = KeysetHandle.generateNew(
//            SignatureKeyTemplates.ECDSA_P256
//        )
//
//        val signer = PublicKeySignFactory.getPrimitive(signPrivateKeysetHandle)
//        val signature = signer.sign(randomBytes)
//
//
//        // Obtain the public key material.
//        val signPublicKeysetHandle = signPrivateKeysetHandle.publicKeysetHandle
//
//        val stream = ByteArrayOutputStream()
//        CleartextKeysetHandle.write(signPublicKeysetHandle, JsonKeysetWriter.withOutputStream(stream))
//
//        val bytes = stream.toByteArray()
//
//        val otherPublicKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(bytes))
//        val verifier = PublicKeyVerifyFactory.getPrimitive(otherPublicKeysetHandle)
//        verifier.verify(signature, randomBytes)
//
//
//        // ENCRYPTING
//
//
//
//        val privateKeysetHandle = KeysetHandle.generateNew(
//            HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
//        )
//
//
//        val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle
//
//        // 2. Get the primitive.
//        val hybridEncrypt = HybridEncryptFactory.getPrimitive(publicKeysetHandle)
////        val hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt::class.java)
//
//        val plaintext: ByteArray = randomBytes
//        val contextInfo: ByteArray = "context info".toByteArray()
//        // 3. Use the primitive.
//        val ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo)
//
//        // DECRYPTING
//
//        // 2. Get the primitive.
////        val hybridDecrypt = privateKeysetHandle.getPrimitive(
////            HybridDecrypt::class.java
////        )
//        val hybridDecrypt = HybridDecryptFactory.getPrimitive(privateKeysetHandle)
//
//        // 3. Use the primitive.
//        val decryptedPlaintextBytes = hybridDecrypt.decrypt(ciphertext, contextInfo)
//        assert(randomBytes.contentEquals(decryptedPlaintextBytes))
//
//        return null
//    }

}