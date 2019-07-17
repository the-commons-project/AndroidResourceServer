package com.curiosityhealth.androidresourceserver.resourceserversampleapp.contentprovider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.AsyncTask
import android.util.Base64
import android.util.Log
import com.auth0.jwt.interfaces.DecodedJWT
import com.curiosityhealth.androidresourceserver.common.authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeAccess
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.common.content.ContentResponse
import com.curiosityhealth.androidresourceserver.common.content.SampleContentResponseItem1
import com.curiosityhealth.androidresourceserver.common.content.SampleContentResponseItem2
import com.curiosityhealth.androidresourceserver.common.resourceserver.ResourceServerRequest
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.token.SampleTokenManager
import com.google.crypto.tink.hybrid.HybridDecryptFactory
import com.google.crypto.tink.hybrid.HybridEncryptFactory
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.subtle.Random
import com.squareup.moshi.Moshi
import io.reactivex.Observable
import io.reactivex.Single
import java.lang.Exception
import java.util.concurrent.CompletableFuture
import java.util.concurrent.FutureTask

abstract class ContentRequestHandler(val authority: String) {
    abstract fun matches(path: Uri) : Boolean
    abstract fun handleContentRequest(path: Uri, clientId: String, token: DecodedJWT?, parameters: Map<String, Any>?, completion: (ContentResponse?, Exception?) -> Unit)
}

class APIViewContentRequestHandler(authority: String, path: String, val view: APIView) {
    companion object {
        val MATCH = 1
    }

    val matcher: UriMatcher = {
        val matcher = UriMatcher(UriMatcher.NO_MATCH)
        matcher.addURI(authority, path, MATCH)
        matcher
    }()

    fun matches(uri: Uri): Boolean {
        val match = matcher.match(uri)
        return match == MATCH
    }
}

class SampleContentRequestHandler1(authority: String, path: String) : ContentRequestHandler(authority) {

    companion object {
        val SAMPLE_DATA_1 = 1
    }

    val matcher: UriMatcher = {
        val matcher = UriMatcher(UriMatcher.NO_MATCH)
        matcher.addURI(authority, path, SAMPLE_DATA_1)
        matcher
    }()

    val requiredScope: ScopeRequest = ScopeRequest("sample_scope_1", ScopeAccess.READ)

    override fun matches(uri: Uri): Boolean {
        val match = matcher.match(uri)
        return match == SAMPLE_DATA_1
    }

    override fun handleContentRequest(path: Uri, clientId: String, token: DecodedJWT?, parameters: Map<String, Any>?, completion: (ContentResponse?, Exception?) -> Unit) {
        //permission checking
        val approvedScopes = SampleClientManager.shared.getApprovedScopes(clientId)
        if (approvedScopes == null || !approvedScopes.contains(requiredScope)) {
            completion(ContentResponse(emptyList()), null)
            return
        }

        val items: List<SampleContentResponseItem1> = listOf(
            SampleContentResponseItem1("item 1", "data 1"),
            SampleContentResponseItem1("item 2", "data 2")
        )

        val moshi = Moshi.Builder().build()
        val jsonAdapter = moshi.adapter(SampleContentResponseItem1::class.java)

        completion(ContentResponse(items.map { jsonAdapter.toJson(it) }), null)
        return
    }
}

class SampleContentRequestHandler2(authority: String, path: String) : ContentRequestHandler(authority) {

    companion object {
        val SAMPLE_DATA_2 = 2
    }

    val matcher: UriMatcher = {
        val matcher = UriMatcher(UriMatcher.NO_MATCH)
        matcher.addURI(authority, path, SAMPLE_DATA_2)
        matcher
    }()

    val requiredScope: ScopeRequest = ScopeRequest("sample_scope_2", ScopeAccess.READ)

    override fun matches(uri: Uri): Boolean {
        val match = matcher.match(uri)
        return match == SAMPLE_DATA_2
    }

    override fun handleContentRequest(path: Uri, clientId: String, token: DecodedJWT?, parameters: Map<String, Any>?, completion: (ContentResponse?, Exception?) -> Unit) {
        //permission checking
        val approvedScopes = SampleClientManager.shared.getApprovedScopes(clientId)
        if (approvedScopes == null || !approvedScopes.contains(requiredScope)) {
            completion(ContentResponse(emptyList()), null)
            return
        }

        val items: List<SampleContentResponseItem2> = listOf(
            SampleContentResponseItem2("item 1", 1),
            SampleContentResponseItem2("item 2", 2)
        )

        val moshi = Moshi.Builder().build()
        val jsonAdapter = moshi.adapter(SampleContentResponseItem2::class.java)

        completion(ContentResponse(items.map { jsonAdapter.toJson(it) }), null)
        return
    }
}



class SampleContentProvider : ContentProvider() {

    companion object {

        val TAG = "SampleContentProvider"

        val authority = "com.curiosityhealth.androidresourceserver.resourceserversampleapp.samplecontentprovider"

    }

    lateinit var contentRequestHandlers: List<APIViewContentRequestHandler>
    override fun onCreate(): Boolean {

        val contentRequestHandlers: List<APIViewContentRequestHandler> = listOf(
            APIViewContentRequestHandler(authority, "sample_data_1", SampleListAPIView1())
        )

        this.contentRequestHandlers = contentRequestHandlers

        return true
    }

    fun getTokenString(uri: Uri, clientId: String) : String? {
        val base64EncryptedToken: String = uri.getQueryParameter("token") ?: return null
        val encryptedTokenData: ByteArray = Base64.decode(base64EncryptedToken, Base64.DEFAULT)
        val base64TokenSignature = uri.getQueryParameter("token_signature") ?: return null
        val tokenSignatureData: ByteArray = Base64.decode(base64TokenSignature, Base64.DEFAULT)

        val clientHandshake = SampleClientManager.shared.getClientHandshake(clientId) ?: return null
        val publicSigningKeysetHandle = clientHandshake.clientPublicSigningKey
        val privateEncryptionKeysetHandle = clientHandshake.serverPrivateEncryptionKey

        //check signature
        val verifier = PublicKeyVerifyFactory.getPrimitive(publicSigningKeysetHandle)
        verifier.verify(tokenSignatureData, encryptedTokenData)

        //decrypt data
        val hybridDecrypt = HybridDecryptFactory.getPrimitive(privateEncryptionKeysetHandle)
        val contextInfo = clientId.toByteArray()
        val decryptedTokenData = hybridDecrypt.decrypt(encryptedTokenData, contextInfo)
        return String(decryptedTokenData)
    }

    fun getToken(uri: Uri, clientId: String) : DecodedJWT? {
        val base64EncryptedToken: String = uri.getQueryParameter("token") ?: return null
        val encryptedTokenData: ByteArray = Base64.decode(base64EncryptedToken, Base64.DEFAULT)
        val base64TokenSignature = uri.getQueryParameter("token_signature") ?: return null
        val tokenSignatureData: ByteArray = Base64.decode(base64TokenSignature, Base64.DEFAULT)

        val clientHandshake = SampleClientManager.shared.getClientHandshake(clientId) ?: return null
        val publicSigningKeysetHandle = clientHandshake.clientPublicSigningKey
        val privateEncryptionKeysetHandle = clientHandshake.serverPrivateEncryptionKey

        //check signature
        val verifier = PublicKeyVerifyFactory.getPrimitive(publicSigningKeysetHandle)
        verifier.verify(tokenSignatureData, encryptedTokenData)

        //decrypt data
        val hybridDecrypt = HybridDecryptFactory.getPrimitive(privateEncryptionKeysetHandle)
        val contextInfo = clientId.toByteArray()
        val decryptedTokenData = hybridDecrypt.decrypt(encryptedTokenData, contextInfo)
        val decryptedToken = String(decryptedTokenData)

        val tokenManager = SampleTokenManager.shared
        return tokenManager.validateAndDecodeAccessToken(decryptedToken)

    }

    private fun generateCursor(clientId: String, apiResponse: APIResponse) : Cursor? {
        val clientHandshake = SampleClientManager.shared.getClientHandshake(clientId) ?: return null

        val privateSigningKey = clientHandshake.serverPrivateSigningKey
        val publicEncryptionKey = clientHandshake.clientPublicEncryptionKey

//        val jsonResponseItems = contentResponse.contentResponseItems.map { it.toJsonObject() }
        //for each item, convert JSON into data and encrypt it, add to cursor
        val columns: Array<String> = arrayOf("encrypted_data", "signature")
        val mc = MatrixCursor(columns)

        apiResponse.JSONStrings?.forEach { contentResponseJsonString ->
            val data = contentResponseJsonString.toByteArray()

            val hybridEncrypt = HybridEncryptFactory.getPrimitive(publicEncryptionKey)
            val contextInfo = clientId.toByteArray()
            val encryptedData = hybridEncrypt.encrypt(data, contextInfo)

            val signer = PublicKeySignFactory.getPrimitive(privateSigningKey)
            val signature = signer.sign(encryptedData)

            val rowBuilder = mc.newRow()
            rowBuilder.add(encryptedData)
            rowBuilder.add(signature)
        }

        return mc
    }

//    fun handleRequest(contentRequestHandler: ContentRequestHandler, uri: Uri, clientId: String, token: DecodedJWT?, parameters: Map<String, Any>?) : ContentResponse? {
//        return contentRequestHandler.handleContentRequest(uri, clientId, token, parameters)
//    }

    class ContentRequestHandlerTask(
        val contentRequestHandler: ContentRequestHandler,
        val uri: Uri,
        val clientId: String,
        val token: DecodedJWT?,
        val parameters: Map<String, Any>?
    ) : AsyncTask<Void, Void, ContentResponse?>() {

        override fun doInBackground(vararg params: Void?): ContentResponse? {

            val contentResponse: ContentResponse? = Single.create<ContentResponse?> { emitter ->
                contentRequestHandler.handleContentRequest(uri, clientId, token, parameters) { contentResponse, exception ->
                    if (contentResponse != null) {
                        emitter.onSuccess(contentResponse)
                    }
                    else {
                        emitter.onError(exception!!)
                    }
                }
            }.blockingGet()

            return contentResponse
        }
    }

    fun handleRequestAsync(contentRequestHandler: ContentRequestHandler, uri: Uri, clientId: String, token: DecodedJWT?, parameters: Map<String, Any>?) : ContentResponse? {

        return ContentRequestHandlerTask(
            contentRequestHandler,
            uri,
            clientId,
            token,
            parameters
        ).execute().get()
    }

    class APIViewRequestHandlerTask(
        val view: APIView,
        val uri: Uri,
        val resourceServerRequest: ResourceServerRequest
    ) : AsyncTask<Void, Void, APIResponse>() {

        override fun doInBackground(vararg params: Void?): APIResponse {
            return Single.create<APIResponse> { emitter ->
                view.handleRequest(uri, resourceServerRequest) { response ->
                    emitter.onSuccess(response)
                }
            }.blockingGet()
        }
    }

    fun handleAPIViewRequestAsync(view: APIView, uri: Uri, resourceServerRequest: ResourceServerRequest) : APIResponse {
        return APIViewRequestHandlerTask(
            view,
            uri,
            resourceServerRequest
        ).execute().get()
    }

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {

        val clientId = uri.getQueryParameter("client_id") ?: return null

        //TODO: this throws if it cant find a match
        val requestHandler: APIViewContentRequestHandler = this.contentRequestHandlers.first { handler ->
            handler.matches(uri)
        }

        val tokenString = getTokenString(uri, clientId)
//        val token = getToken(uri, clientId)
        val resourceServerRequest = ResourceServerRequest(
            tokenString,
            null
        )

        val response = handleAPIViewRequestAsync(requestHandler.view, uri, resourceServerRequest)
        return generateCursor(clientId, response)
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getType(uri: Uri): String? {
        return null
    }

}