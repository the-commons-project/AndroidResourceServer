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

class TokenAuthenticationDelegate : AuthenticationDelegate<Client> {
    override fun authenticate(
        request: ResourceServerRequest,
        completion: (APIViewAuthenticationResult<Client>?, Exception?) -> Unit
    ) {

        //we need to split this out so that client will know if a token
        // is truly bad or it just needs a refresh

        //actually, we will likely delegate this to the auth service introspection
        //receiver, so that will tell us if it's an invalid token or just needs to be refreshed
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
}

class ScopedPermissionsDelegate<RequestParameters>(val requiredScopes: Set<ScopeRequest>) : PermissionsDelegate<Client, RequestParameters> {
    override fun checkPermissions(request: APIRequest<Client, RequestParameters>) {
        val client = request.auth?.client ?: throw APIException.InsufficientPermissions("Invalid client")
        val approvedScopes = SampleClientManager.shared.getApprovedScopes(client.clientId)
        //check that approved scopes is not null AND requiredScopes is a subset of approvedScopes
        //subset is computed by intersecting the 2 sets and ensuring that the count of the subset and the required scopes is equal
        if (approvedScopes != null && approvedScopes.intersect(requiredScopes).count() == requiredScopes.count()) {
            return
        }
        else {
            throw APIException.InsufficientPermissions("Insufficient scope")
        }
    }
}

class SampleListAPIView1 : ListAPIView<Client, Any, SampleContentResponseItem1>() {

    companion object {
        val moshi = Moshi.Builder().build()
        val jsonAdapter = moshi.adapter(SampleContentResponseItem1::class.java)

        val requiredScope: ScopeRequest = ScopeRequest("sample_scope_1", ScopeAccess.READ)
    }

    override val authenticationDelegate = TokenAuthenticationDelegate()

    override fun convertParameters(request: ResourceServerRequest): Any? {
        return null
    }

    override val permissionsDelegate = ScopedPermissionsDelegate<Any>(setOf(requiredScope))

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