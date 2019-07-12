package com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
import com.curiosityhealth.androidresourceserver.common.Authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.Authorization.AuthorizationException
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.resourceserver.activity.AuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager

abstract class AuthorizationBroadcastReceiver<AuthorizationActivityClass: AuthorizationActivity> : BroadcastReceiver() {



    companion object {
        fun <AuthorizationActivityClass: AuthorizationActivity> handleBeginAuthorization(
            context: Context,
            authorizationActivityClass: Class<AuthorizationActivityClass>,
            intent: Intent,
            request: Authorization.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager
        ) {

            //fetch client
            clientManager.client(request.clientId) { client, exception ->

                if (exception != null) {
                    val code = Authorization.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, exception)
                    resultReceiver.send(code, bundle)
                }
                else if (client == null) {
                    val code = Authorization.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = AuthorizationException.UnknownClient(request.clientId)
                    bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                }
                else {

                    //compute scope request
                    //this should be a set intersection of the requested scopes + client scopes + server scopes
                    //for now, just assume that client scopes are a subset of server scopes
//                    val scopes: Set<ScopeRequest> = request.scopes.intersect(client.allowedScopes.map { it.toScopeRequest() })

                    val intent = AuthorizationActivity.newIntent(
                        context,
                        authorizationActivityClass,
                        request,
                        resultReceiver
                    )

                    //what happens if we get a few of these back to back?
                    //maybe have internal state such that we only handle one request at a time
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)



                }

            }

        }
    }

    abstract val clientManager: ClientManager
    abstract val authorizationActivityClass: Class<AuthorizationActivityClass>

    override fun onReceive(context: Context?, intent: Intent?) {

        intent?.let { authorizationIntent ->

            val resultReceiver = authorizationIntent.getParcelableExtra<ResultReceiver>(Authorization.REQUEST_PARAMS.RESPONSE_RECEIVER.name)

            if(context == null) {
                val code = Authorization.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = AuthorizationException.MalformedRequest("Context Null")
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                resultReceiver.send(code, bundle)
                return
            }

            val action = authorizationIntent.action?.let { Authorization.Actions.fromActionString(it) }

            when(action) {
                Authorization.Actions.BEGIN_AUTHORIZATION -> {

                    val request: Authorization.Request? = Authorization.Request.clientIdFromIntent(authorizationIntent)?.let { clientId ->
                        //get server privateEncryptionKeysetHandle
                        //get client publicSigningKeysetHandle
                        clientManager.getClientHandshake(clientId)?.let { clientHandshake ->
                            Authorization.Request.fromIntent(
                                authorizationIntent,
                                clientHandshake.serverPrivateEncryptionKey,
                                clientHandshake.clientPublicSigningKey
                            )
                        }

                    }

                    if (request != null) {
                        AuthorizationBroadcastReceiver.handleBeginAuthorization(
                            context,
                            this.authorizationActivityClass,
                            intent,
                            request,
                            resultReceiver,
                            this.clientManager
                        )
                    }
                    else {
                        val code = Authorization.RESULT_CODE_ERROR
                        val bundle = Bundle()
                        val error = AuthorizationException.MalformedRequest("could not generate request from intent")
                        bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                        resultReceiver.send(code, bundle)
                    }
                    return
                }
                else -> {
                    val code = Authorization.RESULT_CODE_ERROR
                    val bundle = Bundle()
                    val error = AuthorizationException.MalformedRequest("Action not supported")
                    bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                    resultReceiver.send(code, bundle)
                    return
                }
            }


        }
    }

}