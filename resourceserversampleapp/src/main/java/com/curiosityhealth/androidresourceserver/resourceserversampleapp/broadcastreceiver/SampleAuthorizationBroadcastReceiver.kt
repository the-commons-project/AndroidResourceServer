package com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver

import com.curiosityhealth.androidresourceserver.resourceserver.activity.AuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver.AuthorizationBroadcastReceiver
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.activity.SampleAuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager

class SampleAuthorizationBroadcastReceiver : AuthorizationBroadcastReceiver<SampleAuthorizationActivity>() {
    override val clientManager: ClientManager
        get() = SampleClientManager.shared

    override val authorizationActivityClass: Class<SampleAuthorizationActivity>
        get() = SampleAuthorizationActivity::class.java
}