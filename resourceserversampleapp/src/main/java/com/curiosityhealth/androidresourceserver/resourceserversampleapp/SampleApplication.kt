package com.curiosityhealth.androidresourceserver.resourceserversampleapp

import android.app.Application
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.service.SampleHandshakeServiceStorage

class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val filePath = this.filesDir.absolutePath + "/shss/map.ser"
        SampleHandshakeServiceStorage.configure(filePath, this)
    }
}