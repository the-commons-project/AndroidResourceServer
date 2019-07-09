package com.curiosityhealth.androidresourceserver.resourceclientsampleapp

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.curiosityhealth.androidresourceserver.common.BeginHandshake
import com.curiosityhealth.androidresourceserver.resourceclient.AuthorizationClient
import com.curiosityhealth.androidresourceserver.resourceclient.AuthorizationClientConfig

class MainActivity : AppCompatActivity() {

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
            "com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver.SampleHandshakeBroadcastReceiver"
        )

        val authorizationClient = AuthorizationClient(
            this,
            config,
            SampleClientStorage.shared
        )

        authorizationClient.authorize(this) { success, exception ->

        }

//        val context: Context = this
//        val callback = object : BeginHandshake.ResponseReceiver.ResponseReceiverCallBack {
//            override fun onSuccess(data: BeginHandshake.Response) {
//                authorizationClient.validateAndCompleteHandshake(context, data)
//            }
//
//            override fun onError(exception: Exception) {
//                TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
//            }
//
//        }
//
//        authorizationClient.beginHandshake(this, callback)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        super.onActivityResult(requestCode, resultCode, data)
    }
}
