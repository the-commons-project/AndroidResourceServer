package com.curiosityhealth.androidresourceserver.resourceserver.activity

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.curiosityhealth.androidresourceserver.common.authorization.*
import com.curiosityhealth.androidresourceserver.common.CompleteHandshake
import com.curiosityhealth.androidresourceserver.common.Handshake
import com.curiosityhealth.androidresourceserver.common.HandshakeException
import com.curiosityhealth.androidresourceserver.common.VerifyHandshake
import com.curiosityhealth.androidresourceserver.resourceserver.R
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager
import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import java.lang.reflect.Type

abstract class AuthorizationActivity : AppCompatActivity() {

    abstract val clientManager: ClientManager

    data class Response(
        val clientId: String,
        val state: Long,
        val approvedScopes: List<ScopeRequest>
    ) {
        companion object {

            enum class RESPONSE_PARAMS {
                CLIENT_ID, STATE, SCOPES
            }

            fun responseFromBundle(bundle: Bundle) : Response? {

                val clientId = bundle.getString(RESPONSE_PARAMS.CLIENT_ID.name) ?: return null
                val state = bundle.getLong(RESPONSE_PARAMS.STATE.name)
                val requestedScopesJsonString = bundle.getString(RESPONSE_PARAMS.SCOPES.name) ?: return null

                val type: Type = Types.newParameterizedType(List::class.java, ScopeRequest::class.java)
                val moshi = Moshi.Builder().build()
                val jsonAdapter: JsonAdapter<List<ScopeRequest>> = moshi.adapter(type)

                val requestedScopes: List<ScopeRequest> = jsonAdapter.fromJson(requestedScopesJsonString) ?: return null

                return Response(
                    clientId,
                    state,
                    requestedScopes
                )
            }
        }

        fun toBundle() : Bundle {
            val bundle = Bundle()
            bundle.putString(Handshake.RESPONSE_PARAMS.CLIENT_ID.name, this.clientId)
            bundle.putLong(Handshake.RESPONSE_PARAMS.STATE.name, this.state)

            val type: Type = Types.newParameterizedType(List::class.java, ScopeRequest::class.java)
            val moshi = Moshi.Builder().build()
            val jsonAdapter: JsonAdapter<List<ScopeRequest>> = moshi.adapter(type)

            val requestedScopesJsonString: String = jsonAdapter.toJson(this.approvedScopes)
            bundle.putString(RESPONSE_PARAMS.SCOPES.name, requestedScopesJsonString)
            return bundle
        }


    }

    class ResponseReceiver(handler: Handler) : ResultReceiver(handler) {

        interface ResponseReceiverCallBack {
            fun onConsented(response: Response)
            fun onCanceled()
            fun onError(exception: Exception)
        }

        var callback: ResponseReceiverCallBack? = null
        override fun onReceiveResult(resultCode: Int, resultData: Bundle) {

            val cb: ResponseReceiverCallBack? = this.callback

            if (cb != null) {
                if (resultCode == RESULT_CODE_CONSENTED) {

                    val response = Response.responseFromBundle(resultData)
                    if (response != null) {
                        cb.onConsented(response)
                    }
                    else {
                        cb.onError(HandshakeException.MalformedResponse("malformed response"))
                    }

                }
                else if (resultCode == RESULT_CODE_CANCELED) {
                    cb.onCanceled()
                }
                else {
                    val exception: Exception? = resultData.getSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name) as? Exception
                    if (exception != null) {
                        cb.onError(exception)
                    }
                    else {
                        cb.onError(HandshakeException.MalformedResponse("malformed response"))
                    }
                }
            }
        }

    }

    companion object {

        val RESULT_CODE_CONSENTED = 200
        val RESULT_CODE_CANCELED = 300
        val RESULT_CODE_ERROR = 400

        enum class REQUEST_PARAMS {
            CLIENT_ID, STATE, SCOPES, INCLUDE_REFRESH_TOKEN, RESPONSE_RECEIVER
        }

        fun <AuthorizationActivityClass: AuthorizationActivity> newIntent(
            context: Context,
            cls: Class<AuthorizationActivityClass>,
            request: Authorization.Request,
            resultReceiver: ResponseReceiver
        ) : Intent {
            val intent = Intent(context, cls)

            intent.putExtra(REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
            intent.putExtra(REQUEST_PARAMS.STATE.name, request.state)

            val type: Type = Types.newParameterizedType(List::class.java, ScopeRequest::class.java)
            val moshi = Moshi.Builder().build()
            val jsonAdapter: JsonAdapter<List<ScopeRequest>> = moshi.adapter(type)
            val requestedScopesJsonString: String = jsonAdapter.toJson(request.scopes)
            intent.putExtra(REQUEST_PARAMS.SCOPES.name, requestedScopesJsonString)

            intent.putExtra(REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, request.includeRefreshToken)

            intent.putExtra(REQUEST_PARAMS.RESPONSE_RECEIVER.name, resultReceiver)

            return intent
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_authorization)

        val clientId: String = this.intent.getStringExtra(REQUEST_PARAMS.CLIENT_ID.name)
        val state: Long = this.intent.getLongExtra(REQUEST_PARAMS.STATE.name, -1)

        val requestedScopesJsonString = this.intent.getStringExtra(REQUEST_PARAMS.SCOPES.name)
        val type: Type = Types.newParameterizedType(List::class.java, ScopeRequest::class.java)
        val moshi = Moshi.Builder().build()
        val jsonAdapter: JsonAdapter<List<ScopeRequest>> = moshi.adapter(type)

        val responseReceiver: ResultReceiver = this.intent.getParcelableExtra(REQUEST_PARAMS.RESPONSE_RECEIVER.name)

        val requestedScopes: List<ScopeRequest>? = jsonAdapter.fromJson(requestedScopesJsonString)
        if (requestedScopes == null) {
            val code = Authorization.RESULT_CODE_ERROR
            val bundle = Bundle()
            val error = AuthorizationException.MalformedRequest("Invalid Scopes")
            bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
            responseReceiver.send(code, bundle)
            return
        }

        val includeRefreshToken: Boolean = this.intent.getBooleanExtra(REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, true)

        val context = this
        val listView = findViewById<ListView>(R.id.activity_authorization_scope_choice_list_view)

        val cancelButton = findViewById<Button>(R.id.activity_authorization_cancel_button)
        cancelButton.setOnClickListener {
            val code = RESULT_CODE_CANCELED
            val bundle = Bundle()
            responseReceiver.send(code, bundle)
            finish()
        }

        val confirmButton = findViewById<Button>(R.id.activity_authorization_confirm_button)
        confirmButton.setOnClickListener {

            val adaptor = (listView.adapter as? AuthorizationScopeRequestListViewAdaptor)
            if (adaptor == null) {
                val code = Authorization.RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = AuthorizationException.AuthorizationFailed("An error occurred")
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                responseReceiver.send(code, bundle)
            }
            else {
                val approvedScopes: List<ScopeRequest> = adaptor.approvedScopes.map { it.toScopeRequest() }
                //send approved scopes back to the authorization broadcast receiver
                //broadcast receiver will send response back to the original requester

                val response = Response(
                    clientId,
                    state,
                    approvedScopes
                )

                val bundle = response.toBundle()
                responseReceiver.send(Handshake.RESULT_CODE_OK, bundle)
                finish()
            }

        }

        //fetch client
        clientManager.client(clientId) { client, exception ->

            if (exception != null) {
                val code = RESULT_CODE_ERROR
                val bundle = Bundle()
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, exception)
                responseReceiver.send(code, bundle)
            }
            else if (client == null) {
                val code = RESULT_CODE_ERROR
                val bundle = Bundle()
                val error = AuthorizationException.UnknownClient(clientId)
                bundle.putSerializable(Authorization.RESPONSE_PARAMS.EXCEPTION.name, error)
                responseReceiver.send(code, bundle)
            }
            else {
                val scopes: Set<AllowedScope> = client.allowedScopes.filter { requestedScopes.contains(it.toScopeRequest()) }.toSet()
                val readScopes: List<AllowedScope> = scopes
                    .filter { it.access == ScopeAccess.READ }
                    .sortedBy { it.scope.description }
                val writeScopes: List<AllowedScope> = scopes
                    .filter { it.access == ScopeAccess.WRITE }
                    .sortedBy { it.scope.description }

                //compute scopes
                //filter into read and write lists
                //map
                //sort alphabetically

                val adaptor = AuthorizationScopeRequestListViewAdaptor(
                    context,
                    AuthorizationScopeRequestListViewAdaptor.SectionHeader(
                        "${client.description} would like to read the following data types"
                    ),
                    readScopes,
                    AuthorizationScopeRequestListViewAdaptor.SectionHeader(
                        "${client.description} would like to write the following data types"
                    ),
                    writeScopes
                )

                listView.adapter = adaptor
            }

        }

    }

}

class AuthorizationScopeRequestListViewAdaptor(
    val context: Context,
    val readSectionHeader: SectionHeader,
    val readScopes: List<AllowedScope>,
    val writeSectionHeader: SectionHeader,
    val writeScopes: List<AllowedScope>
) : BaseAdapter()  {

    data class SectionHeader(val title: String)

    val hasReadCells: Boolean
        get() = readScopes.count() > 0
    val readCellCount: Int
        get() = if (hasReadCells) readScopes.count() + 1 else 0
    val readCellHeaderIndex: Int?
        get() = if (hasReadCells) 0 else null

    val hasWriteCells: Boolean
        get() = writeScopes.count() > 0
    val writeCellCount: Int
        get() = if (hasWriteCells) writeScopes.count() + 1 else 0
    val writeCellHeaderIndex: Int?
        get() = if (hasWriteCells) readCellCount else null

    private var approvedReadScopeMap: Map<AllowedScope, Boolean> = readScopes.map { Pair(it, false) }.toMap()
    private var approvedWriteScopeMap: Map<AllowedScope, Boolean> = writeScopes.map { Pair(it, false) }.toMap()

    val approvedScopes: Set<AllowedScope>
        get() = approvedReadScopeMap.filter { it.value }.keys +
                approvedWriteScopeMap.filter { it.value }.keys

    override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {

        val item = getItem(position)
        when (item) {
            is SectionHeader -> {
                val sectionHeaderView = convertView ?: LayoutInflater.from(parent!!.context).inflate(R.layout.list_item_authorization_section_header, parent, false)
                val textView = sectionHeaderView.findViewById(R.id.list_item_authorization_section_header_text_view) as TextView
                textView.text = item.title
                return sectionHeaderView
            }

            is AllowedScope -> {
                val scopeChoiceView = convertView ?: LayoutInflater.from(parent!!.context).inflate(R.layout.list_item_authorization_scope_choice, parent, false)
                val switch = scopeChoiceView.findViewById<Switch>(R.id.list_item_authorization_scope_choice_switch_view)
                switch.text = item.scope.description

                switch.setOnCheckedChangeListener { buttonView, isChecked ->
                    if (item.access == ScopeAccess.READ) {
                        approvedReadScopeMap = approvedReadScopeMap.plus(Pair(item, isChecked))
                    }
                    else {
                        approvedWriteScopeMap = approvedWriteScopeMap.plus(Pair(item, isChecked))
                    }
                }

                return scopeChoiceView
            }
            else -> {
                return View(parent!!.context)
            }
        }

    }

    override fun getItem(position: Int): Any {

        val isReadCell = hasReadCells && position < readCellCount
        if (isReadCell) {
            val readPosition = position
            if (readPosition == 0) {
                return readSectionHeader
            }
            else {
                return readScopes[readPosition-1]
            }
        }
        else {
            val writePosition = position - readCellCount
            if (writePosition == 0) {
                return writeSectionHeader
            }
            else {
                return readScopes[writePosition-1]
            }
        }

    }

    override fun getItemId(position: Int): Long {
        return position.toLong()
    }

    override fun getCount(): Int {
        return readCellCount + writeCellCount
    }

}