package com.curiosityhealth.androidresourceserver.resourceserversampleapp.service

import com.curiosityhealth.androidresourceserver.resourceserver.service.HandshakeService

class SampleHandshakeService : HandshakeService() {

    override val handshakeServiceStorage: HandshakeServiceStorage
        get() = SampleHandshakeServiceStorage.shared
}