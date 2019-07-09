package com.curiosityhealth.androidresourceserver.resourceserversampleapp.broadcastreceiver

import com.curiosityhealth.androidresourceserver.resourceserver.broadcastreceiver.HandshakeBroadcastReceiver
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.curiosityhealth.androidresourceserver.resourceserver.service.HandshakeService
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.clientmanagement.SampleClientManager
import com.curiosityhealth.androidresourceserver.resourceserversampleapp.service.SampleHandshakeServiceStorage

class SampleHandshakeBroadcastReceiver : HandshakeBroadcastReceiver() {
    override val handshakeServiceStorage: HandshakeService.HandshakeServiceStorage
        get() = SampleHandshakeServiceStorage.shared

    override val clientManager: ClientManager
        get() = SampleClientManager.shared
}