package com.curiosityhealth.androidresourceserver.resourceserversampleapp

import android.app.Application
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.service.SampleHandshakeServiceStorage
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.token.SampleTokenManager

class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        //potentially merge in handshake service storage into client manager
        SampleHandshakeServiceStorage.configure(this.filesDir.absolutePath + "/shss/map.ser", this)
        SampleClientManager.configure(this.filesDir.absolutePath + "/scm/map.ser", this)
        SampleTokenManager.configure(this.filesDir.absolutePath + "/stm/map.ser", this)

    }
}