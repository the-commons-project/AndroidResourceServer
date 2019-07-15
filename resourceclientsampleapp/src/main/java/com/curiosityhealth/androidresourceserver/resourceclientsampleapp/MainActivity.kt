package com.curiosityhealth.androidresourceserver.resourceclientsampleapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.loader.app.LoaderManager
import androidx.loader.content.CursorLoader
import androidx.loader.content.Loader
import com.curiosityhealth.androidresourceserver.common.authorization.Authorization
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeAccess
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeRequest
import com.curiosityhealth.androidresourceserver.common.authorization.ScopeRequestException
import com.curiosityhealth.androidresourceserver.common.BeginHandshake
import com.curiosityhealth.androidresourceserver.common.content.SampleContentResponseItem1
import com.curiosityhealth.androidresourceserver.common.content.SampleContentResponseItem2
import com.curiosityhealth.androidresourceserver.resourceclient.AuthorizationClient
import com.curiosityhealth.androidresourceserver.resourceclient.AuthorizationClientConfig
import com.squareup.moshi.Moshi
import java.util.*

class MainActivity : AppCompatActivity() {

    companion object {
        val TAG = "MainActivity"
        val AUTHORITY = "com.curiosityhealth.androidresourceserver.resourceserversampleapp.samplecontentprovider"

        val URI_SAMPLE_DATA_1 = Uri.parse(
            "content://" + AUTHORITY + "/" + "sample_data_1"
        )

        val URI_SAMPLE_DATA_2 = Uri.parse(
            "content://" + AUTHORITY + "/" + "sample_data_2"
        )

        private val LOADER_SAMPLE_DATA_1 = 1
        private val LOADER_SAMPLE_DATA_2 = 2
    }

    lateinit var authorizationClient: AuthorizationClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

//        val intent = Intent()
//        intent.component = ComponentName(
//            "com.curiosityhealth.androidresourceserver.resourceserversampleapp",
//            "com.curiosityhealth.androidresourceserver.resourceserversampleapp.ConsentActivity"
//        )
//
//        this.startActivityForResult(intent, 1)

        val config = AuthorizationClientConfig(
            "sample_client_id",
            "com.curiosityhealth.androidresourceserver.resourceserversampleapp",
            "com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver.SampleHandshakeBroadcastReceiver",
            "com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver.SampleAuthorizationBroadcastReceiver"
        )

        val authorizationClient = AuthorizationClient(
            this,
            config,
            SampleClientStorage.shared
        )
        this.authorizationClient = authorizationClient

    }

    override fun onResume() {
        super.onResume()

        val requestedScopes = listOf<ScopeRequest>(
            ScopeRequest("sample_scope_1", ScopeAccess.READ),
            ScopeRequest("sample_scope_2", ScopeAccess.READ)
        )

        if (!authorizationClient.isAuthorized) {
            authorizationClient.authorize(
                this,
                requestedScopes,
                true
            ) { success, exception ->

                //we need to figure out a way to bring the activity back to the foreground
                val intent = Intent(applicationContext, MainActivity::class.java)
                intent.setFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
                startActivity(intent)

//                this.fetchData1() { responseItems, error ->
//                    responseItems?.forEach {
//                        Log.d(TAG, it.toString())
//                    }
//                }

            }
        }
        else {

            authorizationClient.checkHandshake() { success, error ->

                if (success) {

                    this.fetchData1() { responseItems, error ->
                        responseItems?.forEach {
                            Log.d(TAG, it.toString())
                        }
                    }

                    this.fetchData2() { responseItems, error ->
                        responseItems?.forEach {
                            Log.d(TAG, it.toString())
                        }
                    }

                }

            }

        }
    }

    fun fetchData1(completion: (List<SampleContentResponseItem1>?, Throwable?) -> Unit) {

        assert(Looper.myLooper() == Looper.getMainLooper())

        val uri = this.authorizationClient.uriAppendingClientId(URI_SAMPLE_DATA_1)?.let { uri ->
            this.authorizationClient.uriAppendingAccessToken(uri)
        } ?: return

        val columns: Array<String> = arrayOf("encrypted_data", "signature")

        val loaderCallbacks = object : LoaderManager.LoaderCallbacks<Cursor> {
            override fun onCreateLoader(id: Int, args: Bundle?): Loader<Cursor> {

                return CursorLoader(
                    applicationContext,
                    uri,
                    columns,
                    null,
                    null,
                    null
                )
            }

            fun createItem(encryptedData: ByteArray, signature: ByteArray) : SampleContentResponseItem1? {
                val encryptedData = AuthorizationClient.EncryptedData(
                    encryptedData,
                    signature,
                    authorizationClient.config.clientId.toByteArray()
                )

                val data = authorizationClient.decryptData(encryptedData) ?: return null
                val jsonString = String(data)

                val moshi = Moshi.Builder().build()
                val jsonAdapter = moshi.adapter(SampleContentResponseItem1::class.java)

                return jsonAdapter.fromJson(jsonString)
            }

            fun loadFinishedHelper(cursor: Cursor, acc: List<SampleContentResponseItem1>) : List<SampleContentResponseItem1> {

                if (cursor.moveToNext()) {
                    val encryptedData = cursor.getBlob(cursor.getColumnIndexOrThrow("encrypted_data"))
                    val signature = cursor.getBlob(cursor.getColumnIndexOrThrow("signature"))

                    val item = createItem(encryptedData, signature)

                    if (item != null) {
                        val list = acc + listOf(item)
                        return loadFinishedHelper(cursor, list)
                    }
                    else {
                        return loadFinishedHelper(cursor, acc)
                    }
                }
                else {
                    return acc
                }

            }

            override fun onLoadFinished(loader: Loader<Cursor>, cursor: Cursor?) {
                if (cursor == null) {
                    completion(null, null)
                    return
                }
                else {
                    val resources = loadFinishedHelper(cursor, emptyList())
                    completion(resources, null)
                }
            }

            override fun onLoaderReset(loader: Loader<Cursor>) {
                TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
            }
        }


        LoaderManager.getInstance(this).initLoader(LOADER_SAMPLE_DATA_1, null, loaderCallbacks)

    }

    fun fetchData2(completion: (List<SampleContentResponseItem2>?, Throwable?) -> Unit) {

        val uri = this.authorizationClient.uriAppendingClientId(URI_SAMPLE_DATA_2)?.let { uri ->
            this.authorizationClient.uriAppendingAccessToken(uri)
        } ?: return

        val columns: Array<String> = arrayOf("encrypted_data", "signature")

        val loaderCallbacks = object : LoaderManager.LoaderCallbacks<Cursor> {
            override fun onCreateLoader(id: Int, args: Bundle?): Loader<Cursor> {

                return CursorLoader(
                    applicationContext,
                    uri,
                    columns,
                    null,
                    null,
                    null
                )
            }

            fun createItem(encryptedData: ByteArray, signature: ByteArray) : SampleContentResponseItem2? {
                val encryptedData = AuthorizationClient.EncryptedData(
                    encryptedData,
                    signature,
                    authorizationClient.config.clientId.toByteArray()
                )

                val data = authorizationClient.decryptData(encryptedData) ?: return null
                val jsonString = String(data)

                val moshi = Moshi.Builder().build()
                val jsonAdapter = moshi.adapter(SampleContentResponseItem2::class.java)

                return jsonAdapter.fromJson(jsonString)
            }

            fun loadFinishedHelper(cursor: Cursor, acc: List<SampleContentResponseItem2>) : List<SampleContentResponseItem2> {

                if (cursor.moveToNext()) {
                    val encryptedData = cursor.getBlob(cursor.getColumnIndexOrThrow("encrypted_data"))
                    val signature = cursor.getBlob(cursor.getColumnIndexOrThrow("signature"))

                    val item = createItem(encryptedData, signature)

                    if (item != null) {
                        val list = acc + listOf(item)
                        return loadFinishedHelper(cursor, list)
                    }
                    else {
                        return loadFinishedHelper(cursor, acc)
                    }
                }
                else {
                    return acc
                }

            }

            override fun onLoadFinished(loader: Loader<Cursor>, cursor: Cursor?) {
                if (cursor == null) {
                    completion(null, null)
                    return
                }
                else {
                    val resources = loadFinishedHelper(cursor, emptyList())
                    completion(resources, null)
                }
            }

            override fun onLoaderReset(loader: Loader<Cursor>) {
                TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
            }
        }


        LoaderManager.getInstance(this).initLoader(LOADER_SAMPLE_DATA_2, null, loaderCallbacks)

    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        super.onActivityResult(requestCode, resultCode, data)
    }
}
