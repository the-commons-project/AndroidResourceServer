package com.curiosityhealth.androidresourceserver.resourceserversampleapp.contentprovider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.util.Base64
import android.util.Log
import com.auth0.jwt.interfaces.DecodedJWT
import com.curiosityhealth.androidresourceserver.common.Authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeAccess
import com.curiosityhealth.androidresourceserver.common.Authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.token.SampleTokenManager
import com.google.crypto.tink.hybrid.HybridDecryptFactory
import com.google.crypto.tink.hybrid.HybridEncryptFactory
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.signature.PublicKeyVerifyFactory
import com.google.crypto.tink.subtle.Random
import com.google.gson.JsonObject

interface ContentResponseItem {
    fun toJsonObject() : JsonObject
}

data class SampleContentResponseItem1(val identifier: String, val sampleData: String) : ContentResponseItem {
    override fun toJsonObject(): JsonObject {
        val jsonObject: JsonObject = JsonObject()
        jsonObject.addProperty("identifier", this.identifier)
        jsonObject.addProperty("sampleData", this.sampleData)
        return jsonObject
    }
}

data class ContentResponse(val contentResponseItems: List<ContentResponseItem>)

abstract class ContentRequestHandler(val authority: String) {
    abstract fun matches(path: Uri) : Boolean
    abstract fun handleContentRequest(path: Uri, clientId: String, token: DecodedJWT?, parameters: JsonObject?) : ContentResponse?
}

class SampleContentRequestHandler(authority: String, path: String) : ContentRequestHandler(authority) {

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

    override fun handleContentRequest(path: Uri, clientId: String, token: DecodedJWT?, parameters: JsonObject?): ContentResponse? {
        val approvedScopes = SampleClientManager.shared.getApprovedScopes(clientId) ?: return ContentResponse(emptyList())
        if (!approvedScopes.contains(requiredScope)) {
            return ContentResponse(emptyList())
        }

        val items: List<ContentResponseItem> = listOf(
            SampleContentResponseItem1("item 1", "data 1"),
            SampleContentResponseItem1("item 2", "data 2")
        )

        return ContentResponse(items)
    }
}

class SampleContentProvider : ContentProvider() {

    companion object {

        val TAG = "SampleContentProvider"

        val authority = "com.curiosityhealth.androidresourceserver.resourceserversampleapp.samplecontentprovider"

    }

    lateinit var contentRequestHandlers: List<ContentRequestHandler>
    override fun onCreate(): Boolean {

        val contentRequestHandlers: List<ContentRequestHandler> = listOf(
            SampleContentRequestHandler(authority, "sample_data_1")
        )
        this.contentRequestHandlers = contentRequestHandlers

        return true
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
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

    private fun generateCursor(clientId: String, contentResponse: ContentResponse) : Cursor? {
        val clientHandshake = SampleClientManager.shared.getClientHandshake(clientId) ?: return null

        val privateSigningKey = clientHandshake.serverPrivateSigningKey
        val publicEncryptionKey = clientHandshake.clientPublicEncryptionKey

        val jsonResponseItems = contentResponse.contentResponseItems.map { it.toJsonObject() }
        //for each item, convert JSON into data and encrypt it, add to cursor
        val columns: Array<String> = arrayOf("encrypted_data", "signature")
        val mc = MatrixCursor(columns)
        jsonResponseItems.forEach { jsonObject ->
            val data = jsonObject.toString().toByteArray()

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

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {

        val clientId = uri.getQueryParameter("client_id") ?: return null

        //TODO: this throws if it cant find a match
        val requestHandler: ContentRequestHandler? = this.contentRequestHandlers.first { handler ->
            handler.matches(uri)
        }

        val token = getToken(uri, clientId)
        val response = requestHandler?.handleContentRequest(uri, clientId, token, null) ?: return null
        return generateCursor(clientId, response)
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