package com.curiosityhealth.androidresourceserver.resourceserversampleapp.activity

import com.curiosityhealth.androidresourceserver.resourceserver.activity.AuthorizationActivity
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager

class SampleAuthorizationActivity : AuthorizationActivity() {
    override val clientManager: ClientManager
        get() = SampleClientManager.shared
}