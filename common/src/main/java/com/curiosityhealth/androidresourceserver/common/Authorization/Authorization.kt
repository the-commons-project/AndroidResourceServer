package com.curiosityhealth.androidresourceserver.common.authorization

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import com.curiosityhealth.androidresourceserver.common.Handshake
import com.curiosityhealth.androidresourceserver.common.HandshakeException
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridDecryptFactory
import com.google.crypto.tink.hybrid.HybridEncryptFactory
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.subtle.Random
import java.security.GeneralSecurityException
import android.R.attr.data
import com.google.crypto.tink.subtle.Base64
import com.squareup.moshi.JsonClass
import com.squareup.moshi.JsonReader
import com.squareup.moshi.Moshi
import okio.Buffer


class Authorization {

    companion object {
        val RESULT_CODE_OK = 200
        val RESULT_CODE_ERROR = 400
    }

    enum class Actions {
        BEGIN_AUTHORIZATION;

        fun toActionString(): String {
            when (this) {
                BEGIN_AUTHORIZATION -> {
                    return "com.curiosityhealth.androidresourceserver.intent.action.BEGIN_AUTHORIZATION"
                }
            }
        }

        companion object {
            fun fromActionString(actionString: String) : Actions? {
                when (actionString) {
                    "com.curiosityhealth.androidresourceserver.intent.action.BEGIN_AUTHORIZATION" -> { return BEGIN_AUTHORIZATION}
                    else -> { return null }
                }
            }
        }
    }

    enum class REQUEST_PARAMS {
        CLIENT_ID, ENCRYPTED_PARAMETERS, SIGNATURE, RESPONSE_RECEIVER
    }

    enum class REQUEST_JSON_PARAMS {
        CLIENT_ID, STATE, SCOPES, INCLUDE_REFRESH_TOKEN, NONCE
    }

    enum class RESPONSE_PARAMS {
        ENCRYPTED_PARAMETERS, SIGNATURE, EXCEPTION
    }

    enum class RESPONSE_JSON_PARAMS {
        ACCESS_TOKEN, REFRESH_TOKEN, STATE, NONCE
    }

    @JsonClass(generateAdapter = true)
    data class Request(
        val clientId: String,
        val state: Long,
        val scopes: List<ScopeRequest>,
        val includeRefreshToken: Boolean
    ) {

        data class EncryptedParameters(
            val clientId: String,
            val encryptedJSON: ByteArray,
            val signature: ByteArray
        ) {

            companion object {

                @Throws(GeneralSecurityException::class)
                fun fromIntent(
                    intent: Intent
                ) : EncryptedParameters? {
                    val clientId = intent.getStringExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name) ?: return null

                    val encryptedParameters = intent.getByteArrayExtra(Authorization.REQUEST_PARAMS.ENCRYPTED_PARAMETERS.name) ?: return null
                    val signature = intent.getByteArrayExtra(Authorization.REQUEST_PARAMS.SIGNATURE.name) ?: return null
                    return EncryptedParameters(
                        clientId,
                        encryptedParameters,
                        signature
                    )

                }
            }

        }

        companion object {

            fun clientIdFromIntent(intent: Intent) : String? {
                return intent.getStringExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name)
            }

            @Throws(GeneralSecurityException::class, AuthorizationException.MalformedRequest::class)
            fun fromEncryptedParameters(
                encryptedParameters: EncryptedParameters,
                privateEncryptionKeysetHandle: KeysetHandle,
                publicSigningKeysetHandle: KeysetHandle
            ) : Request {

                //check signature
                val verifier = PublicKeyVerifyFactory.getPrimitive(publicSigningKeysetHandle)
                verifier.verify(encryptedParameters.signature, encryptedParameters.encryptedJSON)

                //decrypt data
                val hybridDecrypt = HybridDecryptFactory.getPrimitive(privateEncryptionKeysetHandle)
                val contextInfo = encryptedParameters.clientId.toByteArray()
                val decryptedBytes = hybridDecrypt.decrypt(encryptedParameters.encryptedJSON, contextInfo)

                val moshi = Moshi.Builder().build()
                val jsonAdapter = moshi.adapter(Request::class.java)

                val request: Request = jsonAdapter.fromJson(String(decryptedBytes)) ?: throw AuthorizationException.MalformedRequest("Invalid parameters")

                if (encryptedParameters.clientId != request.clientId) {
                    throw AuthorizationException.MalformedRequest("Client ID does not match")
                }

                return request
            }

            @Throws(GeneralSecurityException::class, AuthorizationException.MalformedRequest::class)
            fun fromIntent(
                intent: Intent,
                privateEncryptionKeysetHandle: KeysetHandle,
                publicSigningKeysetHandle: KeysetHandle
            ) : Request? {
                val clientId = intent.getStringExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name) ?: return null

                val encryptedJSON = intent.getByteArrayExtra(Authorization.REQUEST_PARAMS.ENCRYPTED_PARAMETERS.name) ?: return null
                val signature = intent.getByteArrayExtra(Authorization.REQUEST_PARAMS.SIGNATURE.name) ?: return null

                val encryptedParameters = EncryptedParameters(
                    clientId,
                    encryptedJSON,
                    signature
                )

                return Request.fromEncryptedParameters(
                    encryptedParameters,
                    privateEncryptionKeysetHandle,
                    publicSigningKeysetHandle
                )
            }

            @Throws(GeneralSecurityException::class)
            fun requestIntent(
                serverPackage: String,
                handshakeServiceClass: String,
                request: Request,
                responseReceiver: ResponseReceiver,
                publicEncryptionKeysetHandle: KeysetHandle,
                privateSigningKeysetHandle: KeysetHandle
            ) : Intent {


                val intent = Intent()

                intent.component = ComponentName(
                    serverPackage,
                    handshakeServiceClass
                )

                intent.action = Authorization.Actions.BEGIN_AUTHORIZATION.toActionString()

                val encryptedRequestParameters = request.getEncryptedParameters(
                    publicEncryptionKeysetHandle,
                    privateSigningKeysetHandle
                )

                intent.putExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name, encryptedRequestParameters.clientId)
                intent.putExtra(Authorization.REQUEST_PARAMS.ENCRYPTED_PARAMETERS.name, encryptedRequestParameters.encryptedJSON)
                intent.putExtra(Authorization.REQUEST_PARAMS.SIGNATURE.name, encryptedRequestParameters.signature)

                intent.putExtra(Authorization.REQUEST_PARAMS.RESPONSE_RECEIVER.name, responseReceiver)
                return intent
            }

        }

        @Throws(GeneralSecurityException::class)
        fun getEncryptedParameters(
            publicEncryptionKeysetHandle: KeysetHandle,
            privateSigningKeysetHandle: KeysetHandle
        ) : EncryptedParameters {

            val moshi = Moshi.Builder().build()
            val jsonAdapter = moshi.adapter(Request::class.java)

            val parameterString = jsonAdapter.toJson(this)
            val parameterBytes: ByteArray = parameterString.toByteArray()

            val hybridEncrypt = HybridEncryptFactory.getPrimitive(publicEncryptionKeysetHandle)
            val contextInfo = this.clientId.toByteArray()
            val encryptedJSON = hybridEncrypt.encrypt(parameterBytes, contextInfo)

            val signer = PublicKeySignFactory.getPrimitive(privateSigningKeysetHandle)
            val signature = signer.sign(encryptedJSON)

            return EncryptedParameters(
                this.clientId,
                encryptedJSON,
                signature
            )

        }


    }


    @JsonClass(generateAdapter = true)
    data class Response(
        val accessToken: String,
        val refreshtoken: String,
        val state: Long
    ) {

        class ResponsePartial(val encryptedParameters: EncryptedParameters) {

            fun response(
                clientId: String,
                privateEncryptionKeysetHandle: KeysetHandle,
                publicSigningKeysetHandle: KeysetHandle
            ) : Response {
                return Response.fromEncryptedParameters(
                    clientId,
                    this.encryptedParameters,
                    privateEncryptionKeysetHandle,
                    publicSigningKeysetHandle
                )
            }

        }

        data class EncryptedParameters(
            val encryptedJSON: ByteArray,
            val signature: ByteArray
        ) {

            companion object {

                @Throws(GeneralSecurityException::class)
                fun fromBundle(
                    bundle: Bundle
                ) : EncryptedParameters? {
                    val encryptedParameters = bundle.getByteArray(Authorization.RESPONSE_PARAMS.ENCRYPTED_PARAMETERS.name) ?: return null
                    val signature = bundle.getByteArray(Authorization.REQUEST_PARAMS.SIGNATURE.name) ?: return null
                    return EncryptedParameters(
                        encryptedParameters,
                        signature
                    )

                }
            }

        }

        companion object {

            fun responsePartialFromBundle(
                bundle: Bundle
            ) : ResponsePartial? {
                val encryptedJSON = bundle.getByteArray(Authorization.RESPONSE_PARAMS.ENCRYPTED_PARAMETERS.name) ?: return null
                val signature = bundle.getByteArray(Authorization.RESPONSE_PARAMS.SIGNATURE.name) ?: return null

                val encryptedParameters = Response.EncryptedParameters(
                    encryptedJSON,
                    signature
                )

                return ResponsePartial(encryptedParameters)
            }

//            fun responseFromBundle(
//                bundle: Bundle,
//                clientId: String,
//                privateEncryptionKeysetHandle: KeysetHandle,
//                publicSigningKeysetHandle: KeysetHandle
//            ) : Response? {
//
//                val encryptedJSON = bundle.getByteArray(Authorization.RESPONSE_PARAMS.ENCRYPTED_PARAMETERS.name) ?: return null
//                val signature = bundle.getByteArray(Authorization.RESPONSE_PARAMS.SIGNATURE.name) ?: return null
//
//                val encryptedParameters = Response.EncryptedParameters(
//                    encryptedJSON,
//                    signature
//                )
//
//                return Response.fromEncryptedParameters(
//                    clientId,
//                    encryptedParameters,
//                    privateEncryptionKeysetHandle,
//                    publicSigningKeysetHandle
//                )
//            }

            @Throws(GeneralSecurityException::class, AuthorizationException.MalformedRequest::class)
            fun fromEncryptedParameters(
                clientId: String,
                encryptedParameters: Response.EncryptedParameters,
                privateEncryptionKeysetHandle: KeysetHandle,
                publicSigningKeysetHandle: KeysetHandle
            ) : Response {

                //check signature
                val verifier = PublicKeyVerifyFactory.getPrimitive(publicSigningKeysetHandle)
                verifier.verify(encryptedParameters.signature, encryptedParameters.encryptedJSON)

                //decrypt data
                val hybridDecrypt = HybridDecryptFactory.getPrimitive(privateEncryptionKeysetHandle)
                val contextInfo = clientId.toByteArray()
                val decryptedBytes = hybridDecrypt.decrypt(encryptedParameters.encryptedJSON, contextInfo)

                val moshi = Moshi.Builder().build()
                val jsonAdapter = moshi.adapter(Response::class.java)

                return jsonAdapter.fromJson(String(decryptedBytes)) ?: throw AuthorizationException.MalformedRequest("Invalid parameters")
            }
        }

        fun toBundle(
            clientId: String,
            publicEncryptionKeysetHandle: KeysetHandle,
            privateSigningKeysetHandle: KeysetHandle
        ) : Bundle {
            val bundle = Bundle()

            val encryptedRequestParameters = this.getEncryptedParameters(
                clientId,
                publicEncryptionKeysetHandle,
                privateSigningKeysetHandle
            )

            bundle.putByteArray(Authorization.RESPONSE_PARAMS.ENCRYPTED_PARAMETERS.name, encryptedRequestParameters.encryptedJSON)
            bundle.putByteArray(Authorization.RESPONSE_PARAMS.SIGNATURE.name, encryptedRequestParameters.signature)

            return bundle
        }

        @Throws(GeneralSecurityException::class)
        fun getEncryptedParameters(
            clientId: String,
            publicEncryptionKeysetHandle: KeysetHandle,
            privateSigningKeysetHandle: KeysetHandle
        ) : Response.EncryptedParameters {

            val moshi = Moshi.Builder().build()
            val jsonAdapter = moshi.adapter(Response::class.java)

            val parameterString = jsonAdapter.toJson(this)
            val parameterBytes: ByteArray = parameterString.toByteArray()

            val hybridEncrypt = HybridEncryptFactory.getPrimitive(publicEncryptionKeysetHandle)
            val contextInfo = clientId.toByteArray()
            val encryptedJSON = hybridEncrypt.encrypt(parameterBytes, contextInfo)

            val signer = PublicKeySignFactory.getPrimitive(privateSigningKeysetHandle)
            val signature = signer.sign(encryptedJSON)

            return Response.EncryptedParameters(
                encryptedJSON,
                signature
            )

        }
    }

    class ResponseReceiver(handler: Handler) : ResultReceiver(handler) {

        interface ResponseReceiverCallBack {
            fun onSuccess(responsePartial: Response.ResponsePartial)
            fun onError(exception: Exception)
        }

        var callback: ResponseReceiverCallBack? = null
        override fun onReceiveResult(resultCode: Int, resultData: Bundle) {

            val cb: ResponseReceiverCallBack? = this.callback

            if (cb != null) {
                if (resultCode == RESULT_CODE_OK) {

                    val responsePartial = Response.responsePartialFromBundle(resultData)
                    if (responsePartial != null) {
                        cb.onSuccess(responsePartial)
                    }
                    else {
                        cb.onError(HandshakeException.MalformedResponse("malformed response"))
                    }

                } else {
                    val exception: Exception? = resultData.getSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name) as? Exception
                    if (exception != null) {
                        cb.onError(exception)
                    }
                    else {
                        cb.onError(HandshakeException.MalformedResponse("malformed response"))
                    }
                }
            }
        }

    }

}

