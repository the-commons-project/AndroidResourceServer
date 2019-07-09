package com.curiosityhealth.androidresourceserver.common

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import kotlin.math.acos

sealed class HandshakeException(s: String) : Exception(s) {
    class MalformedRequest(s: String): HandshakeException(s)
    class MalformedResponse(s: String): HandshakeException(s)
    class InvalidState(s: String): HandshakeException(s)
}

class Handshake {

    companion object {
        val RESULT_CODE_OK = 200
        val RESULT_CODE_ERROR = 400
    }

    enum class Actions {
        BEGIN_HANDSHAKE, COMPLETE_HANDSHAKE, VERIFY_HANDSHAKE;

        fun toActionString(): String {
            when (this) {
                BEGIN_HANDSHAKE -> {
                    return "com.curiosityhealth.androidresourceserver.intent.action.BEGIN_HANDSHAKE"
                }
                COMPLETE_HANDSHAKE -> {
                    return "com.curiosityhealth.androidresourceserver.intent.action.COMPLETE_HANDSHAKE"
                }
                VERIFY_HANDSHAKE -> {
                    return "com.curiosityhealth.androidresourceserver.intent.action.VERIFY_HANDSHAKE"
                }
            }
        }

        companion object {
            fun fromActionString(actionString: String) : Actions? {
                when (actionString) {
                    "com.curiosityhealth.androidresourceserver.intent.action.BEGIN_HANDSHAKE" -> { return BEGIN_HANDSHAKE}
                    "com.curiosityhealth.androidresourceserver.intent.action.COMPLETE_HANDSHAKE" -> { return COMPLETE_HANDSHAKE}
                    "com.curiosityhealth.androidresourceserver.intent.action.VERIFY_HANDSHAKE" -> { return VERIFY_HANDSHAKE}
                    else -> { return null }
                }
            }
        }
    }

    enum class REQUEST_PARAMS {
        CLIENT_ID, STATE, SIGNING_PUBLIC_KEY, ENCRYPTION_PUBLIC_KEY, DATA, SIGNATURE, ENCRYPTED_DATA, CONTEXT_INFO, RESPONSE_RECEIVER
    }

    enum class RESPONSE_PARAMS {
        CLIENT_ID, STATE, SIGNING_PUBLIC_KEY, ENCRYPTION_PUBLIC_KEY, DATA, SIGNATURE, ENCRYPTED_DATA, CONTEXT_INFO, SUCCESS, EXCEPTION
    }

}

class BeginHandshake {

    data class Request(
        val clientId: String,
        val state: Long,
        val signingPublicKey: ByteArray,
        val encryptionPublicKey: ByteArray,
        val m1Data: ByteArray,
        val m1Signature: ByteArray
    ) {
        companion object {

            fun fromIntent(intent: Intent) : Request? {
                val clientId = intent.getStringExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name) ?: return null
                val state = intent.getLongExtra(Handshake.REQUEST_PARAMS.STATE.name, 0)
                val signingPublicKey = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.SIGNING_PUBLIC_KEY.name) ?: return null
                val encryptionPublicKey = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.ENCRYPTION_PUBLIC_KEY.name) ?: return null
                val data = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.DATA.name) ?: return null
                val signature = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.SIGNATURE.name) ?: return null

                return Request(
                    clientId,
                    state,
                    signingPublicKey,
                    encryptionPublicKey,
                    data,
                    signature
                )
            }

            fun requestIntent(
                serverPackage: String,
                handshakeServiceClass: String,
                request: Request,
                responseReceiver: ResponseReceiver
            ) : Intent {
                val intent = Intent()

                intent.component = ComponentName(
                    serverPackage,
                    handshakeServiceClass
                )

                intent.action = Handshake.Actions.BEGIN_HANDSHAKE.toActionString()

                intent.putExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
                intent.putExtra(Handshake.REQUEST_PARAMS.STATE.name, request.state)
                intent.putExtra(Handshake.REQUEST_PARAMS.SIGNING_PUBLIC_KEY.name, request.signingPublicKey)
                intent.putExtra(Handshake.REQUEST_PARAMS.ENCRYPTION_PUBLIC_KEY.name, request.encryptionPublicKey)
                intent.putExtra(Handshake.REQUEST_PARAMS.DATA.name, request.m1Data)
                intent.putExtra(Handshake.REQUEST_PARAMS.SIGNATURE.name, request.m1Signature)
                intent.putExtra(Handshake.REQUEST_PARAMS.RESPONSE_RECEIVER.name, responseReceiver)

                return intent
            }
        }
    }



    data class Response(
        val clientId: String,
        val state: Long,
        val signingPublicKey: ByteArray,
        val encryptionPublicKey: ByteArray,
        val m2Data: ByteArray,
        val m2Signature: ByteArray,
        val m1EncryptedData: ByteArray,
        val contextInfo: ByteArray
    ) {

        companion object {
            fun responseFromBundle(bundle: Bundle) : Response? {

                val clientId = bundle.getString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name) ?: return null
                val state = bundle.getLong(Handshake.RESPONSE_PARAMS.STATE.name)
                val signingPublicKey = bundle.getByteArray(Handshake.RESPONSE_PARAMS.SIGNING_PUBLIC_KEY.name) ?: return null
                val encryptionPublicKey = bundle.getByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTION_PUBLIC_KEY.name) ?: return null
                val data = bundle.getByteArray(Handshake.RESPONSE_PARAMS.DATA.name) ?: return null
                val signature = bundle.getByteArray(Handshake.RESPONSE_PARAMS.SIGNATURE.name) ?: return null
                val encryptedData = bundle.getByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTED_DATA.name) ?: return null
                val contextInfo = bundle.getByteArray(Handshake.RESPONSE_PARAMS.CONTEXT_INFO.name) ?: return null

                return Response(
                    clientId,
                    state,
                    signingPublicKey,
                    encryptionPublicKey,
                    data,
                    signature,
                    encryptedData,
                    contextInfo
                )
            }
        }

        fun toBundle() : Bundle {
            val bundle = Bundle()
            bundle.putString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name, this.clientId)
            bundle.putLong(Handshake.RESPONSE_PARAMS.STATE.name, this.state)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.SIGNING_PUBLIC_KEY.name, this.signingPublicKey)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTION_PUBLIC_KEY.name, this.encryptionPublicKey)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.DATA.name, this.m2Data)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.SIGNATURE.name, this.m2Signature)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTED_DATA.name, this.m1EncryptedData)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.CONTEXT_INFO.name, this.contextInfo)

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

class CompleteHandshake {
    data class Request(
        val clientId: String,
        val state: Long,
        val m2EncryptedData: ByteArray,
        val contextInfo: ByteArray
    ) {

        companion object {

            fun fromIntent(intent: Intent) : Request? {
                val clientId = intent.getStringExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name) ?: return null
                val state = intent.getLongExtra(Handshake.REQUEST_PARAMS.STATE.name, 0)
//                val signingPublicKey = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.SIGNING_PUBLIC_KEY.name) ?: return null
//                val encryptionPublicKey = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.ENCRYPTION_PUBLIC_KEY.name) ?: return null
                val m2EncryptedData = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.ENCRYPTED_DATA.name) ?: return null
                val contextInfo = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.CONTEXT_INFO.name) ?: return null

                return Request(
                    clientId,
                    state,
                    m2EncryptedData,
                    contextInfo
                )
            }

            fun requestIntent(
                serverPackage: String,
                handshakeServiceClass: String,
                request: Request,
                responseReceiver: ResponseReceiver
            ) : Intent {
                val intent = Intent()

                intent.component = ComponentName(
                    serverPackage,
                    handshakeServiceClass
                )

                intent.action = Handshake.Actions.COMPLETE_HANDSHAKE.toActionString()

                intent.putExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
                intent.putExtra(Handshake.REQUEST_PARAMS.STATE.name, request.state)
                intent.putExtra(Handshake.REQUEST_PARAMS.ENCRYPTED_DATA.name, request.m2EncryptedData)
                intent.putExtra(Handshake.REQUEST_PARAMS.CONTEXT_INFO.name, request.contextInfo)
                intent.putExtra(Handshake.REQUEST_PARAMS.RESPONSE_RECEIVER.name, responseReceiver)

                return intent
            }
        }

    }
    data class Response(
        val clientId: String,
        val state: Long,
        val success: Boolean
    ) {
        companion object {
            fun responseFromBundle(bundle: Bundle) : CompleteHandshake.Response? {
                val clientId = bundle.getString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name) ?: return null
                val state = bundle.getLong(Handshake.RESPONSE_PARAMS.STATE.name)
                val success = bundle.getBoolean(Handshake.RESPONSE_PARAMS.SUCCESS.name, false)

                return Response(
                    clientId,
                    state,
                    success
                )
            }
        }

        fun toBundle() : Bundle {
            val bundle = Bundle()
            bundle.putString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name, this.clientId)
            bundle.putLong(Handshake.RESPONSE_PARAMS.STATE.name, this.state)
            bundle.putBoolean(Handshake.RESPONSE_PARAMS.SUCCESS.name, this.success)
            return bundle
        }
    }

    class ResponseReceiver(handler: Handler) : ResultReceiver(handler) {

        interface ResponseReceiverCallBack {
            fun onSuccess(response: CompleteHandshake.Response)
            fun onError(exception: Exception)
        }

        var callback: ResponseReceiverCallBack? = null
        override fun onReceiveResult(resultCode: Int, resultData: Bundle) {

            val cb: ResponseReceiverCallBack? = this.callback

            if (cb != null) {
                if (resultCode == Handshake.RESULT_CODE_OK) {

                    val response = CompleteHandshake.Response.responseFromBundle(resultData)
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

class VerifyHandshake {

    data class Request(
        val clientId: String,
        val data: ByteArray,
        val signature: ByteArray,
        val encryptedData: ByteArray,
        val contextInfo: ByteArray
    ) {
        companion object {

            fun fromIntent(intent: Intent) : Request? {
                val clientId = intent.getStringExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name) ?: return null
                val data = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.DATA.name) ?: return null
                val signature = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.SIGNATURE.name) ?: return null
                val encryptedData = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.ENCRYPTED_DATA.name) ?: return null
                val contextInfo = intent.getByteArrayExtra(Handshake.REQUEST_PARAMS.CONTEXT_INFO.name) ?: return null

                return Request(
                    clientId,
                    data,
                    signature,
                    encryptedData,
                    contextInfo
                )
            }

            fun requestIntent(
                serverPackage: String,
                handshakeServiceClass: String,
                request: Request,
                responseReceiver: ResponseReceiver
            ) : Intent {
                val intent = Intent()

                intent.component = ComponentName(
                    serverPackage,
                    handshakeServiceClass
                )

                intent.action = Handshake.Actions.VERIFY_HANDSHAKE.toActionString()

                intent.putExtra(Handshake.REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
                intent.putExtra(Handshake.REQUEST_PARAMS.DATA.name, request.data)
                intent.putExtra(Handshake.REQUEST_PARAMS.SIGNATURE.name, request.signature)
                intent.putExtra(Handshake.REQUEST_PARAMS.ENCRYPTED_DATA.name, request.encryptedData)
                intent.putExtra(Handshake.REQUEST_PARAMS.CONTEXT_INFO.name, request.contextInfo)
                intent.putExtra(Handshake.REQUEST_PARAMS.RESPONSE_RECEIVER.name, responseReceiver)

                return intent
            }
        }
    }



    data class Response(
        val clientId: String,
        val data: ByteArray,
        val signature: ByteArray,
        val encryptedData: ByteArray,
        val contextInfo: ByteArray
    ) {

        companion object {
            fun responseFromBundle(bundle: Bundle) : Response? {

                val clientId = bundle.getString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name) ?: return null
                val data = bundle.getByteArray(Handshake.RESPONSE_PARAMS.DATA.name) ?: return null
                val signature = bundle.getByteArray(Handshake.RESPONSE_PARAMS.SIGNATURE.name) ?: return null
                val encryptedData = bundle.getByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTED_DATA.name) ?: return null
                val contextInfo = bundle.getByteArray(Handshake.RESPONSE_PARAMS.CONTEXT_INFO.name) ?: return null

                return Response(
                    clientId,
                    data,
                    signature,
                    encryptedData,
                    contextInfo
                )
            }
        }

        fun toBundle() : Bundle {
            val bundle = Bundle()
            bundle.putString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name, this.clientId)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.DATA.name, this.data)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.SIGNATURE.name, this.signature)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.ENCRYPTED_DATA.name, this.encryptedData)
            bundle.putByteArray(Handshake.RESPONSE_PARAMS.CONTEXT_INFO.name, this.contextInfo)

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

