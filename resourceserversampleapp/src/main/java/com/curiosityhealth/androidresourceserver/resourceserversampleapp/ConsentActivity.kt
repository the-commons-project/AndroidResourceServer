package com.curiosityhealth.androidresourceserver.resourceserversampleapp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.PersistableBundle
import androidx.appcompat.app.AppCompatActivity

class ConsentActivity : AppCompatActivity() {


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_consent)

        val intent = this.intent

        val newIntent = Intent()
        setResult(Activity.RESULT_OK)
        finish()
    }

}