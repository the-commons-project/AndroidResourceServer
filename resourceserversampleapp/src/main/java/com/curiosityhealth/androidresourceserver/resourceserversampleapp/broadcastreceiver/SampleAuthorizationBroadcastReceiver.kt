package com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver

import com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver.AuthorizationBroadcastReceiver
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager

class SampleAuthorizationBroadcastReceiver : AuthorizationBroadcastReceiver() {
    override val clientManager: ClientManager
        get() = SampleClientManager.shared
}