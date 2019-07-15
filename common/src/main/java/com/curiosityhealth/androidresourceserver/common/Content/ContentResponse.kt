package com.curiosityhealth.androidresourceserver.common.content

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class SampleContentResponseItem1(val identifier: String, val sampleString: String) {

}

@JsonClass(generateAdapter = true)
data class SampleContentResponseItem2(val identifier: String, val sampleInt: String) {

}

data class ContentResponse(val contentResponseJsonStrings: List<String>)