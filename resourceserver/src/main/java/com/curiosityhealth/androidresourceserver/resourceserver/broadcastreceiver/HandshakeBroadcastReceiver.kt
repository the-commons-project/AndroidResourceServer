package com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
import com.curiosityhealth.androidresourceserver.common.*
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientHandshake
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserver.service.HandshakeService
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetReader
import com.google.crypto.tink.JsonKeysetWriter
import com.google.crypto.tink.KeysetHandle
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
import kotlin.math.sign

abstract class HandshakeBroadcastReceiver : BroadcastReceiver() {

    companion object {
        fun handleBeginHandshake(
            intent: Intent,
            request: BeginHandshake.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager,
            handshakeServiceStorage: HandshakeService.HandshakeServiceStorage
        ) {

            //perform any client checking here

            //clear client info
            handshakeServiceStorage.clear(request.clientId)

            //store state
            handshakeServiceStorage.storeState(request.clientId, request.state)

            try {
                val clientSigningPublicKey = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(request.signingPublicKey))
                handshakeServiceStorage.storeClientPublicSigningKey(
                    clientSigningPublicKey,
                    request.clientId,
                    request.state
                )

                val clientEncryptionPublicKey = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(request.encryptionPublicKey))
                handshakeServiceStorage.storeClientPublicEncryptionKey(
                    clientEncryptionPublicKey,
                    request.clientId,
                    request.state
                )

                val verifier = PublicKeyVerifyFactory.getPrimitive(clientSigningPublicKey)
                verifier.verify(request.m1Signature, request.m1Data)

                val hybridEncrypt = HybridEncryptFactory.getPrimitive(clientEncryptionPublicKey)

                val contextInfo = Random.randBytes(64)

                val encryptedData = hybridEncrypt.encrypt(request.m1Data, contextInfo)

                val m2Data = Random.randBytes(1024)
                handshakeServiceStorage.storeM2Data(m2Data, request.clientId, request.state)

                val serverSigningPrivateKeysetHandle = KeysetHandle.generateNew(
                    SignatureKeyTemplates.ECDSA_P256
                )

                handshakeServiceStorage.storeServerPrivateSigningKey(
                    serverSigningPrivateKeysetHandle,
                    request.clientId,
                    request.state
                )

                val serverSigningPublicKeysetHandle = serverSigningPrivateKeysetHandle.publicKeysetHandle
                val serverSigningPublicKeysetHandleByteStream = ByteArrayOutputStream()
                CleartextKeysetHandle.write(
                    serverSigningPublicKeysetHandle,
                    JsonKeysetWriter.withOutputStream(serverSigningPublicKeysetHandleByteStream)
                )

                val serverEncryptionPrivateKeysetHandle = KeysetHandle.generateNew(
                    HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
                )

                handshakeServiceStorage.storeServerPrivateEncryptionKey(
                    serverEncryptionPrivateKeysetHandle,
                    request.clientId,
                    request.state
                )

                val serverEncryptionPublicKeysetHandle = serverEncryptionPrivateKeysetHandle.publicKeysetHandle
                val serverEncryptionPublicKeysetHandleByteStream = ByteArrayOutputStream()
                CleartextKeysetHandle.write(
                    serverEncryptionPublicKeysetHandle,
                    JsonKeysetWriter.withOutputStream(serverEncryptionPublicKeysetHandleByteStream)
                )

                val signer = PublicKeySignFactory.getPrimitive(serverSigningPrivateKeysetHandle)
                val signature = signer.sign(m2Data)

                val response = BeginHandshake.Response(
                    request.clientId,
                    request.state,
                    serverSigningPublicKeysetHandleByteStream.toByteArray(),
                    serverEncryptionPublicKeysetHandleByteStream.toByteArray(),
                    m2Data,
                    signature,
                    encryptedData,
                    contextInfo
                )

                val bundle = response.toBundle()
                resultReceiver.send(Handshake.RESULT_CODE_OK, bundle)
            }
            catch (gse: GeneralSecurityException) {

                //clear client info
                handshakeServiceStorage.clear(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, gse)
                resultReceiver.send(code, bundle)
            }
            catch (ioe: IOException) {

                //clear client info
                handshakeServiceStorage.clear(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, ioe)
                resultReceiver.send(code, bundle)
            }

        }

        fun handleCompleteHandshake(
            intent: Intent,
            request: CompleteHandshake.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager,
            handshakeServiceStorage: HandshakeService.HandshakeServiceStorage
        ) {

            //perform any client checking here

            //check clientId and state are valid
            val savedState = handshakeServiceStorage.getState(request.clientId)
            if (savedState == null ||
                savedState != request.state) {

                //clear client info
                handshakeServiceStorage.clear(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = HandshakeException.MalformedRequest("Unknown client or invalid state")
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                resultReceiver.send(code, bundle)
                return
            }

            try {

                //look up keyset handle and m2Data
                val serverEncryptionPrivateKeysetHandle = handshakeServiceStorage.getServerPrivateEncryptionKey(
                    request.clientId,
                    request.state
                )

                val m2Data = handshakeServiceStorage.getM2Data(
                    request.clientId,
                    request.state
                )

                if (serverEncryptionPrivateKeysetHandle == null ||
                    m2Data == null) {

                    //clear client info
                    handshakeServiceStorage.clear(request.clientId)

                    val code = Handshake.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = HandshakeException.MalformedRequest("Unknown client or invalid state")
                    bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }

                val hybridDecrypt = HybridDecryptFactory.getPrimitive(serverEncryptionPrivateKeysetHandle)
                val decryptedM2Data = hybridDecrypt.decrypt(request.m2EncryptedData, request.contextInfo)
                assert(m2Data.contentEquals(decryptedM2Data))
                if (!m2Data.contentEquals(decryptedM2Data)) {

                    //clear client info
                    handshakeServiceStorage.clear(request.clientId)

                    val code = Handshake.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = HandshakeException.MalformedRequest("Invalid data")
                    bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }

                val saved = this.saveClientHandshake(
                    request.clientId,
                    request.state,
                    clientManager,
                    handshakeServiceStorage
                )

                if (!saved) {

                    //clear client info
                    handshakeServiceStorage.clear(request.clientId)

                    val code = Handshake.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = HandshakeException.MalformedRequest("Could not save client info")
                    bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }

                val response = CompleteHandshake.Response(
                    request.clientId,
                    request.state,
                    true
                )

                val bundle = response.toBundle()
                resultReceiver.send(Handshake.RESULT_CODE_OK, bundle)
            }
            catch (gse: GeneralSecurityException) {

                //clear client info
                handshakeServiceStorage.clear(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, gse)
                resultReceiver.send(code, bundle)
            }
            catch (ioe: IOException) {

                //clear client info
                handshakeServiceStorage.clear(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, ioe)
                resultReceiver.send(code, bundle)
            }

        }

        fun handleVerifyHandshake(
            intent: Intent,
            request: VerifyHandshake.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager
        ) {

            val clientHandshake = clientManager.getClientHandshake(request.clientId)
            if (clientHandshake == null) {
                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = HandshakeException.MalformedRequest("Needs handshake")
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                resultReceiver.send(code, bundle)
                return
            }

            try {

                //using client public signing key, verify signature
                val verifier = PublicKeyVerifyFactory.getPrimitive(clientHandshake.clientPublicSigningKey)
                verifier.verify(request.signature, request.data)

                //using server private encryption key, decrypt data
                val hybridDecrypt = HybridDecryptFactory.getPrimitive(clientHandshake.serverPrivateEncryptionKey)
                val decryptedData = hybridDecrypt.decrypt(request.encryptedData, request.contextInfo)

                //compare decrypted data to data
                if (!request.data.contentEquals(decryptedData)) {

                    //clear client handshake info
                    clientManager.clearClientHandshake(request.clientId)

                    val code = Handshake.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = HandshakeException.MalformedRequest("Invalid data")
                    bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }

                //generate new data and sign it using server private signing key
                val data = Random.randBytes(1024)
                val signer = PublicKeySignFactory.getPrimitive(clientHandshake.serverPrivateSigningKey)
                val signature = signer.sign(data)

                //encrypt data using client public encryption key
                val hybridEncrypt = HybridEncryptFactory.getPrimitive(clientHandshake.clientPublicEncryptionKey)
                val contextInfo = Random.randBytes(64)
                val encryptedData = hybridEncrypt.encrypt(data, contextInfo)

                val response = VerifyHandshake.Response(
                    request.clientId,
                    data,
                    signature,
                    encryptedData,
                    contextInfo
                )

                val bundle = response.toBundle()
                resultReceiver.send(Handshake.RESULT_CODE_OK, bundle)
            }
            catch (gse: GeneralSecurityException) {

                //clear client handshake info
                clientManager.clearClientHandshake(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, gse)
                resultReceiver.send(code, bundle)
            }
            catch (ioe: IOException) {

                //clear client handshake info
                clientManager.clearClientHandshake(request.clientId)

                val code = Handshake.RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, ioe)
                resultReceiver.send(code, bundle)
            }

        }

        fun getClientHandshake(
            clientId: String,
            state: Long,
            handshakeServiceStorage: HandshakeService.HandshakeServiceStorage
        ) : ClientHandshake? {
            val clientPublicSigningKey: KeysetHandle = handshakeServiceStorage.getClientPublicSigningKey(clientId, state) ?: return null
            val clientPublicEncryptionKey: KeysetHandle = handshakeServiceStorage.getClientPublicEncryptionKey(clientId, state) ?: return null
            val serverPrivateSigningKey: KeysetHandle = handshakeServiceStorage.getServerPrivateSigningKey(clientId, state) ?: return null
            val serverPrivateEncryptionKey: KeysetHandle = handshakeServiceStorage.getServerPrivateEncryptionKey(clientId, state) ?: return null

            return ClientHandshake(
                clientId,
                clientPublicSigningKey,
                clientPublicEncryptionKey,
                serverPrivateSigningKey,
                serverPrivateEncryptionKey
            )
        }

        fun saveClientHandshake(
            clientId: String,
            state: Long,
            clientManager: ClientManager,
            handshakeServiceStorage: HandshakeService.HandshakeServiceStorage
        ) : Boolean {

            val clientHandshake = this.getClientHandshake(clientId, state, handshakeServiceStorage) ?: return false
            clientManager.registerClientHandshake(
                clientId,
                clientHandshake
            )

            handshakeServiceStorage.clear(clientId)

            return true
        }
    }

    abstract val clientManager: ClientManager
    abstract val handshakeServiceStorage : HandshakeService.HandshakeServiceStorage
//    abstract val handshakeClientRegistrationStorage : HandshakeService.HandshakeClientRegistrationStorage

    override fun onReceive(context: Context?, intent: Intent?) {
        intent?.let { handshakeIntent ->

            val resultReceiver = handshakeIntent.getParcelableExtra<ResultReceiver>(Handshake.REQUEST_PARAMS.RESPONSE_RECEIVER.name)

            val action = handshakeIntent.action?.let { Handshake.Actions.fromActionString(it) }

            when(action) {
                Handshake.Actions.BEGIN_HANDSHAKE -> {
                    val request = BeginHandshake.Request.fromIntent(handshakeIntent)
                    if (request != null) {
                        handleBeginHandshake(
                            intent,
                            request,
                            resultReceiver,
                            this.clientManager,
                            this.handshakeServiceStorage
                        )
                    }
                    else {
                        val code = Handshake.RESULT_CODE_ERROR
                        val bundle = Bundle()
                        val error = HandshakeException.MalformedRequest("could not generate request from intent")
                        bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                        resultReceiver.send(code, bundle)
                    }
                    return
                }
                Handshake.Actions.COMPLETE_HANDSHAKE -> {
                    val request = CompleteHandshake.Request.fromIntent(handshakeIntent)
                    if (request != null) {
                        handleCompleteHandshake(
                            intent,
                            request,
                            resultReceiver,
                            this.clientManager,
                            this.handshakeServiceStorage
                        )
                    }
                    else {
                        val code = Handshake.RESULT_CODE_ERROR
                        val bundle = Bundle()
                        val error = HandshakeException.MalformedRequest("could not generate request from intent")
                        bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                        resultReceiver.send(code, bundle)
                    }
                    return
                }
                Handshake.Actions.VERIFY_HANDSHAKE -> {
                    val request = VerifyHandshake.Request.fromIntent(handshakeIntent)
                    if (request != null) {
                        handleVerifyHandshake(
                            intent,
                            request,
                            resultReceiver,
                            this.clientManager
                        )
                    }
                    else {
                        val code = Handshake.RESULT_CODE_ERROR
                        val bundle = Bundle()
                        val error = HandshakeException.MalformedRequest("could not generate request from intent")
                        bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                        resultReceiver.send(code, bundle)
                    }
                    return
                }
                else -> {
                    val code = Handshake.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = HandshakeException.MalformedRequest("Action not supported")
                    bundle.putSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }
            }


        }
    }

}