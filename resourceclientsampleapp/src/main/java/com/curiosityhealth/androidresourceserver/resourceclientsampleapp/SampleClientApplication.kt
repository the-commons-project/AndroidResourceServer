package com.curiosityhealth.androidresourceserver.resourceclientsampleapp

import android.app.Application

class SampleClientApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        SampleClientStorage.configure(this.filesDir.absolutePath + "/scs/map.ser", this)

    }

}