package com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import com.curiosityhealth.androidresourceserver.common.authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.authorization.AuthorizationException
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.common.VerifyHandshake
import com.curiosityhealth.androidresourceserver.resourceserver.activity.AuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.curiosityhealth.androidresourceserver.common.Handshake
import com.curiosityhealth.androidresourceserver.resourceserver.token.TokenManager


abstract class AuthorizationBroadcastReceiver<AuthorizationActivityClass: AuthorizationActivity> : BroadcastReceiver() {

    companion object {

        fun generateTokensAndSendResponse(
            request: Authorization.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager,
            tokenManager: TokenManager
        ) {
            val oneDay: Int = 24 * 60 * 60
            val oneYear: Int = 365 * oneDay
            val accessToken = tokenManager.generateAccessToken(request.clientId, oneDay)
            val refreshToken = tokenManager.generateRefreshToken(request.clientId, oneYear)

            if (accessToken == null || refreshToken == null) {
                val code = Authorization.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = AuthorizationException.TokenError("Cannot generate token")
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                resultReceiver.send(code, bundle)
                return
            }

            val response = Authorization.Response(
                accessToken,
                refreshToken,
                request.state
            )

            val handshake = clientManager.getClientHandshake(request.clientId)
            if (handshake == null) {
                val code = Authorization.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = AuthorizationException.MalformedResponse("Handshake not available")
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                resultReceiver.send(code, bundle)
                return
            }

            val bundle = response.toBundle(
                request.clientId,
                handshake.clientPublicEncryptionKey,
                handshake.serverPrivateSigningKey
            )

            resultReceiver.send(Authorization.RESULT_CODE_OK, bundle)
        }

        fun <AuthorizationActivityClass: AuthorizationActivity> handleBeginAuthorization(
            context: Context,
            authorizationActivityClass: Class<AuthorizationActivityClass>,
            intent: Intent,
            request: Authorization.Request,
            resultReceiver: ResultReceiver,
            clientManager: ClientManager,
            tokenManager: TokenManager
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

                    val completeAuthorizationCallback = object : AuthorizationActivity.ResponseReceiver.ResponseReceiverCallBack {
                        override fun onConsented(response: AuthorizationActivity.Response) {

                            //TODO: create a consent event and store it
                            //This will be used to get the latest consent. We can change this at a later date from within the server application
                            //ideally, we'd still want those tokens to work, just with the modified scopes
                            //for now, we'll just store a set of scopes for the client

                            clientManager.setApprovedScopes(request.clientId, response.approvedScopes)
                            generateTokensAndSendResponse(
                                request,
                                resultReceiver,
                                clientManager,
                                tokenManager
                            )

                        }

                        override fun onCanceled() {
                            //TODO: Review this behavior. Maybe we just want to send a cancel notice back to client?
                            //if cancel, clear scopes but still return tokens
                            clientManager.clearApprovedScopes(request.clientId)
                            generateTokensAndSendResponse(
                                request,
                                resultReceiver,
                                clientManager,
                                tokenManager
                            )
                        }

                        override fun onError(exception: Exception) {
                            val code = Authorization.RESULT_CODE_ERROR
                            val bundle = Bundle()
                            bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, exception)
                            resultReceiver.send(code, bundle)
                        }
                    }

                    val authorizationActivityResponseReceiver = AuthorizationActivity.ResponseReceiver(Handler(context.mainLooper))
                    authorizationActivityResponseReceiver.callback = completeAuthorizationCallback

                    val authorizationActivityIntent = AuthorizationActivity.newIntent(
                        context,
                        authorizationActivityClass,
                        request,
                        authorizationActivityResponseReceiver
                    )

                    //what happens if we get a few of these back to back?
                    //maybe have internal state such that we only handle one request at a time
                    authorizationActivityIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(authorizationActivityIntent)

                }

            }

        }
    }

    abstract val clientManager: ClientManager
    abstract val tokenManager: TokenManager
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
                        handleBeginAuthorization(
                            context,
                            this.authorizationActivityClass,
                            intent,
                            request,
                            resultReceiver,
                            this.clientManager,
                            this.tokenManager
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