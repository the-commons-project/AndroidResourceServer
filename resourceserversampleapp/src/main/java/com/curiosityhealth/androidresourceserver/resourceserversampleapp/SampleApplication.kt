package com.curiosityhealth.androidresourceserver.resourceserversampleapp

import android.app.Application
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.service.SampleHandshakeServiceStorage

class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        //potentially merge in handshake service storage into client manager
        SampleHandshakeServiceStorage.configure(this.filesDir.absolutePath + "/shss/map.ser", this)
        SampleClientManager.configure(this.filesDir.absolutePath + "/scm/map.ser", this)

    }
}