package com.curiosityhealth.androidresourceserver.common.Authorization

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import com.curiosityhealth.androidresourceserver.common.Handshake
import com.curiosityhealth.androidresourceserver.common.HandshakeException

class Authorization {

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
        CLIENT_ID, STATE, SCOPES, RESPONSE_RECEIVER, INCLUDE_REFRESH_TOKEN
    }

    enum class RESPONSE_PARAMS {
        TOKEN, STATE, EXCEPTION
    }

    data class Request(
        val clientId: String,
        val state: Long,
        val scopes: Set<ScopeRequest>,
        val includeRefreshToken: Boolean
    ) {
        companion object {

            fun fromIntent(intent: Intent) : Request? {
                val clientId = intent.getStringExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name) ?: return null
                val state = intent.getLongExtra(Authorization.REQUEST_PARAMS.STATE.name, 0)
                val scopes: Set<ScopeRequest> = intent.getStringArrayListExtra(Authorization.REQUEST_PARAMS.SCOPES.name)?.let { scopeStringList ->
                    scopeStringList.mapNotNull { ScopeRequest.fromScopeRequestString(it) }
                }?.toSet() ?: return null
                val includeRefreshToken = intent.getBooleanExtra(Authorization.REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, false)

                return Request(
                    clientId,
                    state,
                    scopes,
                    includeRefreshToken
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

                intent.action = Authorization.Actions.BEGIN_AUTHORIZATION.toActionString()

                intent.putExtra(Authorization.REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
                intent.putExtra(Authorization.REQUEST_PARAMS.STATE.name, request.state)
                intent.putExtra(Authorization.REQUEST_PARAMS.SCOPES.name, request.scopes.map { it.toScopeRequestString() }.toTypedArray())
                intent.putExtra(Authorization.REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, request.includeRefreshToken)

                intent.putExtra(Authorization.REQUEST_PARAMS.RESPONSE_RECEIVER.name, responseReceiver)

                return intent
            }
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

