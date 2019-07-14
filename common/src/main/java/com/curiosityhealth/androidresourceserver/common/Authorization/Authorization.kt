package com.curiosityhealth.androidresourceserver.common.Authorization

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
import com.google.gson.*
import java.security.GeneralSecurityException
import android.R.attr.data
import com.google.crypto.tink.subtle.Base64


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

    class Request(
        val clientId: String,
        val state: Long,
        val scopes: Set<ScopeRequest>,
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

                val jsonString = String(decryptedBytes)
                val jsonObject: JsonObject = JsonParser().parse(jsonString).asJsonObject

                val paramClientId: String = jsonObject.getAsJsonPrimitive(Authorization.REQUEST_JSON_PARAMS.CLIENT_ID.name).let { if (it.isString) it.asString else null } ?: throw AuthorizationException.MalformedRequest("Client ID not included in request")
                if (encryptedParameters.clientId != paramClientId) {
                    throw AuthorizationException.MalformedRequest("Client ID does not match")
                }

                val state: Long = jsonObject.getAsJsonPrimitive(Authorization.REQUEST_JSON_PARAMS.STATE.name).let { if (it.isNumber) it.asNumber else null }?.toLong() ?: throw AuthorizationException.MalformedRequest("State not included in request")

                val scopeArray: JsonArray = jsonObject.getAsJsonArray(Authorization.REQUEST_JSON_PARAMS.SCOPES.name)
                val convertScope: (JsonElement) -> ScopeRequest? = convertScope@{ jsonElement ->
                    if (jsonElement.isJsonPrimitive) {
                        val primitive = jsonElement.asJsonPrimitive
                        if (primitive.isString) {
                            return@convertScope ScopeRequest.fromScopeRequestString(primitive.asString)
                        }
                    }

                    null
                }
                val scopes: Set<ScopeRequest> = scopeArray.asIterable().mapNotNull(convertScope).toSet()

                val includeRefreshToken: Boolean = jsonObject.getAsJsonPrimitive(Authorization.REQUEST_JSON_PARAMS.INCLUDE_REFRESH_TOKEN.name).let { if (it.isBoolean) it.asBoolean else null } ?: throw AuthorizationException.MalformedRequest("includeRefreshToken not included in request")

                return Request(
                    encryptedParameters.clientId,
                    state,
                    scopes,
                    includeRefreshToken
                )
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

            val parameters: JsonObject = JsonObject()
            parameters.addProperty(Authorization.REQUEST_JSON_PARAMS.CLIENT_ID.name, this.clientId)
            parameters.addProperty(Authorization.REQUEST_JSON_PARAMS.STATE.name, this.state)
            val scopes: JsonArray = this.scopes.map { it.toScopeRequestString() }.fold(JsonArray()) { acc, scopeRequestString ->
                acc.add(scopeRequestString)
                acc
            }

            parameters.add(Authorization.REQUEST_JSON_PARAMS.SCOPES.name, scopes)
            parameters.addProperty(Authorization.REQUEST_JSON_PARAMS.INCLUDE_REFRESH_TOKEN.name, this.includeRefreshToken)
            val nonce = Base64.encodeToString(Random.randBytes(64), Base64.DEFAULT)
            parameters.addProperty(Authorization.REQUEST_JSON_PARAMS.NONCE.name, nonce)

            val parameterString = parameters.toString()
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

                val jsonString = String(decryptedBytes)
                val jsonObject: JsonObject = JsonParser().parse(jsonString).asJsonObject

                val accessToken: String = jsonObject.getAsJsonPrimitive(Authorization.RESPONSE_JSON_PARAMS.ACCESS_TOKEN.name).let { if (it.isString) it.asString else null } ?: throw AuthorizationException.MalformedResponse("Access Token not included in response")
                val refreshToken: String = jsonObject.getAsJsonPrimitive(Authorization.RESPONSE_JSON_PARAMS.REFRESH_TOKEN.name).let { if (it.isString) it.asString else null } ?: throw AuthorizationException.MalformedResponse("Refresh Token not included in response")
                val state: Long = jsonObject.getAsJsonPrimitive(Authorization.RESPONSE_JSON_PARAMS.STATE.name).let { if (it.isNumber) it.asNumber else null }?.toLong() ?: throw AuthorizationException.MalformedRequest("State not included in request")

                return Response(
                    accessToken,
                    refreshToken,
                    state
                )
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

            val parameters: JsonObject = JsonObject()
            parameters.addProperty(Authorization.RESPONSE_JSON_PARAMS.ACCESS_TOKEN.name, this.accessToken)
            parameters.addProperty(Authorization.RESPONSE_JSON_PARAMS.REFRESH_TOKEN.name, this.refreshtoken)
            parameters.addProperty(Authorization.RESPONSE_JSON_PARAMS.STATE.name, this.state)
            val nonce = Base64.encodeToString(Random.randBytes(64), Base64.DEFAULT)
            parameters.addProperty(Authorization.RESPONSE_JSON_PARAMS.NONCE.name, nonce)

            val parameterString = parameters.toString()
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

