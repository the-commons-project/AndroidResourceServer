package com.curiosityhealth.androidresourceserver.resourceserversampleapp.contentprovider

import com.auth0.jwt.interfaces.DecodedJWT
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeAccess
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.common.content.ContentResponse
import com.curiosityhealth.androidresourceserver.common.content.SampleContentResponseItem1
import com.curiosityhealth.androidresourceserver.common.resourceserver.ResourceServerRequest
import com.curiosityhealth.androidresourceserver.resourceserver.client.Client
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserver.token.TokenManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.token.SampleTokenManager
import com.squareup.moshi.Moshi
import java.lang.Exception

class SampleListAPIView1 : ListAPIView<Client, Any, SampleContentResponseItem1>() {

    companion object {
        val moshi = Moshi.Builder().build()
        val jsonAdapter = moshi.adapter(SampleContentResponseItem1::class.java)

        val requiredScope: ScopeRequest = ScopeRequest("sample_scope_1", ScopeAccess.READ)
    }

    override fun authenticate(
        request: ResourceServerRequest,
        completion: (APIViewAuthenticationResult<Client>?, Exception?) -> Unit
    ) {

        val token = request.token
        if (token == null) {
            val error = APIException.AuthorizationFailed("No token provided")
            completion(null, error)
            return
        }

        val jwt = SampleTokenManager.shared.validateAndDecodeAccessToken(token)
        if (jwt == null) {
            val error = APIException.AuthorizationFailed("Invalid token")
            completion(null, error)
            return
        }

        val clientId = SampleTokenManager.shared.getClientIdFromToken(jwt)
        if (clientId == null) {
            val error = APIException.AuthorizationFailed("Invalid token")
            completion(null, error)
            return
        }

        SampleClientManager.shared.client(clientId) { client, exception ->
            if (client == null) {
                completion(null, exception)
            }
            else {
                val result = APIViewAuthenticationResult(
                    jwt,
                    client
                )

                completion(result, null)
            }
        }

    }

    override fun convertParameters(request: ResourceServerRequest): Any? {
        return null
    }

    override fun checkPermissions(request: APIRequest<Client, Any>) {
        val client = request.auth?.client ?: throw APIException.InsufficientPermissions("Invalid client")
        val approvedScopes = SampleClientManager.shared.getApprovedScopes(client.clientId)
        if (approvedScopes == null || !approvedScopes.contains(requiredScope)) {
            throw APIException.InsufficientPermissions("Insufficient scope")
        }
    }

    override fun getObjects(request: APIRequest<Client, Any>): List<SampleContentResponseItem1> {
        return listOf(
            SampleContentResponseItem1("item 1", "data 1"),
            SampleContentResponseItem1("item 2", "data 2")
        )
    }

    override fun serialize(obj: SampleContentResponseItem1): String {
        return jsonAdapter.toJson(obj)
    }
}