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
        CLIENT_ID, STATE, SCOPES, INCLUDE_REFRESH_TOKEN
    }

    enum class RESPONSE_PARAMS {
        TOKEN, STATE, ENCRYPTED_PARAMETERS, EXCEPTION
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
        val token: String,
        val state: Long
    ) {

        companion object {
            fun responseFromBundle(bundle: Bundle) : Response? {

                val token = bundle.getString(Authorization.RESPONSE_PARAMS.TOKEN.name) ?: return null
                val state = bundle.getLong(Authorization.RESPONSE_PARAMS.STATE.name)

                return Response(
                    token,
                    state
                )
            }
        }

        fun toBundle() : Bundle {
            val bundle = Bundle()
            bundle.putString(Authorization.RESPONSE_PARAMS.TOKEN.name, this.token)
            bundle.putLong(Authorization.RESPONSE_PARAMS.STATE.name, this.state)

            return bundle
        }
    }



    class ResponseReceiver(handler: Handler) : ResultReceiver(handler) {

        interface ResponseReceiverCallBack {
            fun onSuccess(response: Response)
            fun onError(exception: Exception)
        }

        var callback: ResponseReceiverCallBack? = null
        override fun onReceiveResult(resultCode: Int, resultData: Bundle) {

            val cb: ResponseReceiverCallBack? = this.callback

            if (cb != null) {
                if (resultCode == Handshake.RESULT_CODE_OK) {

                    val response = Response.responseFromBundle(resultData)
                    if (response != null) {
                        cb.onSuccess(response)
                    }
                    else {
                        cb.onError(HandshakeException.MalformedResponse("malformed response"))
                    }

                } else {
                    val exception: Exception? = resultData.getSerializable(Handshake.RESPONSE_PARAMS.EXCEPTION.name) as? Exception
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

