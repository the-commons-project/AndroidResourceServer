package com.curiosityhealth.androidresourceserver.resourceserversampleapp.contentprovider

import android.net.Uri
import com.auth0.jwt.interfaces.DecodedJWT
import com.curiosityhealth.androidresourceserver.common.content.ContentResponse
import com.curiosityhealth.androidresourceserver.common.resourceserver.ResourceServerRequest
import com.curiosityhealth.androidresourceserver.resourceserver.activity.AuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserver.client.Client
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.token.SampleTokenManager
import io.reactivex.Maybe
import io.reactivex.Single
import java.lang.Exception
import java.security.GeneralSecurityException
import java.util.*

data class APIViewAuthenticationResult<Client>(
    val token: DecodedJWT?,
    val client: Client?
)

data class APIRequest<Client, RequestParameters>(
    val uri: Uri,
    val auth: APIViewAuthenticationResult<Client>?,
    val parameters: RequestParameters?
)

data class APIResponse(
    val code: Int,
    val JSONStrings: List<String>?,
    val exception: Exception?
)

sealed class APIException(s: String) : Exception(s) {
    class AuthorizationFailed(s: String) : APIException(s)
    class MalformedRequest(s: String) : APIException(s)
    class InsufficientPermissions(s: String) : APIException(s)
    class NotFound(s: String) : APIException(s)
}

interface APIView {
    fun handleRequest(uri: Uri, request: ResourceServerRequest, completion: (APIResponse) -> Unit)
}

data class APIRoute(
    val path: String,
    val view: APIView
)

interface AuthenticationDelegate<Client> {
    fun authenticate(
        request: ResourceServerRequest,
        completion: (APIViewAuthenticationResult<Client>?, Exception?) -> Unit
    )
}

class DefaultAuthenticationDelegate<Client> : AuthenticationDelegate<Client> {
    override fun authenticate(
        request: ResourceServerRequest,
        completion: (APIViewAuthenticationResult<Client>?, Exception?) -> Unit
    ) {
        completion(null, null)
    }
}

interface PermissionsDelegate<Client, RequestParameters> {
    @Throws(APIException.InsufficientPermissions::class)
    fun checkPermissions(request: APIRequest<Client, RequestParameters>)
}

class DefaultPermissionsDelegate<Client, RequestParameters> : PermissionsDelegate<Client, RequestParameters> {
    override fun checkPermissions(request: APIRequest<Client, RequestParameters>) {

    }
}

abstract class GenericReadAPIView<Client, RequestParameters, ResponseObject> : APIView {

    //TODO: potientially return exception here to indicate that authentication has failed
//    abstract fun authenticate(request: ResourceServerRequest, completion: (APIViewAuthenticationResult<Client>?, Exception?) -> Unit)
    open val authenticationDelegate: AuthenticationDelegate<Client>
        get() = DefaultAuthenticationDelegate()

    @Throws(APIException.MalformedRequest::class)
    abstract fun convertParameters(request: ResourceServerRequest) : RequestParameters?

    open val permissionsDelegate: PermissionsDelegate<Client, RequestParameters>
        get() = DefaultPermissionsDelegate()

    abstract fun getObjects(request: APIRequest<Client, RequestParameters>) : List<ResponseObject>

    abstract fun serialize(obj: ResponseObject) : String

    override fun handleRequest(uri: Uri, request: ResourceServerRequest, completion: (APIResponse) -> Unit) {

        val authOpt: Maybe<APIViewAuthenticationResult<Client>>
        try {
            authOpt = Single.create<Maybe<APIViewAuthenticationResult<Client>>> { emitter ->
                authenticationDelegate.authenticate(request) { auth, error ->

                    if (error != null) {
                        emitter.onError(error)
                    }
                    else if (auth == null) {
                        val empty: Maybe<APIViewAuthenticationResult<Client>> = Maybe.empty()
                        emitter.onSuccess(empty)
                    }
                    else {
                        emitter.onSuccess(Maybe.just(auth))
                    }

                }
            }.blockingGet()
        }
        catch (e: APIException.AuthorizationFailed) {
            val response = APIResponse(401, null, e)
            completion(response)
            return
        }

        val auth: APIViewAuthenticationResult<Client>? = if (authOpt.isEmpty.blockingGet()) null else authOpt.blockingGet()

        //check for throws
        val parameters: RequestParameters?
        try {
            parameters = convertParameters(request)
        }
        catch (e: APIException.MalformedRequest) {
            val response = APIResponse(400, null, e)
            completion(response)
            return
        }

        val apiRequest: APIRequest<Client, RequestParameters> = APIRequest(uri, auth, parameters)

        //check for throws
        try {
            permissionsDelegate.checkPermissions(apiRequest)
        }
        catch (e: APIException.InsufficientPermissions) {
            val response = APIResponse(403, null, e)
            completion(response)
            return
        }

        val objects = this.getObjects(apiRequest)

        val serializedObjects = objects.map { serialize(it) }

        val response = APIResponse(200, serializedObjects, null)
        completion(response)

    }

}

abstract class ListAPIView<Client, RequestParameters, ResponseObject> : GenericReadAPIView<Client, RequestParameters, ResponseObject>()

abstract class ReadAPIView<Client, RequestParameters, ResponseObject> : GenericReadAPIView<Client, RequestParameters, ResponseObject>() {

    @Throws(APIException.NotFound::class, APIException.MalformedRequest::class)
    override fun getObjects(request: APIRequest<Client, RequestParameters>) : List<ResponseObject> {
        val identifier = request.uri.lastPathSegment ?: throw APIException.MalformedRequest("unknown identifier")
        return listOf(this.getObject(identifier, request))
    }

    @Throws(APIException.NotFound::class)
    abstract fun getObject(identifier: String, request: APIRequest<Client, RequestParameters>) : ResponseObject

}

