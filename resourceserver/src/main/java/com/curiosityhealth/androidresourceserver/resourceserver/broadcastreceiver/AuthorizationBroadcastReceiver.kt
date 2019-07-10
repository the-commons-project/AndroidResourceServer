package com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager

abstract class AuthorizationBroadcastReceiver : BroadcastReceiver() {

    abstract val clientManager: ClientManager

    override fun onReceive(context: Context?, intent: Intent?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        //do any checking


        //start authorization activity
    }

}