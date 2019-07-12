package com.curiosityhealth.androidresourceserver.resourceserver.activity

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.ResultReceiver
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import com.curiosityhealth.androidresourceserver.common.Authorization.*
import com.curiosityhealth.androidresourceserver.resourceserver.R
import com.curiosityhealth.androidresourceserver.resourceserver.client.ClientManager

abstract class AuthorizationActivity : AppCompatActivity() {

    abstract val clientManager: ClientManager

    companion object {

        enum class REQUEST_PARAMS {
            CLIENT_ID, STATE, SCOPES, INCLUDE_REFRESH_TOKEN, RESPONSE_RECEIVER
        }

        fun <AuthorizationActivityClass: AuthorizationActivity> newIntent(
            context: Context,
            cls: Class<AuthorizationActivityClass>,
            request: Authorization.Request,
            resultReceiver: ResultReceiver
        ) : Intent {
            val intent = Intent(context, cls)

            intent.putExtra(REQUEST_PARAMS.CLIENT_ID.name, request.clientId)
            intent.putExtra(REQUEST_PARAMS.STATE.name, request.state)
            intent.putExtra(REQUEST_PARAMS.SCOPES.name, request.scopes.map { it.toScopeRequestString() }.toTypedArray())
            intent.putExtra(REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, request.includeRefreshToken)

            intent.putExtra(REQUEST_PARAMS.RESPONSE_RECEIVER.name, resultReceiver)

            return intent
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_authorization)

        val clientId: String = this.intent.getStringExtra(REQUEST_PARAMS.CLIENT_ID.name)
        val scopeArray: Array<String> = this.intent.getStringArrayExtra(REQUEST_PARAMS.SCOPES.name)
        val requestedScopes: Set<ScopeRequest> = scopeArray.mapNotNull { ScopeRequest.fromScopeRequestString(it) }.toSet()
        val includeRefreshToken: Boolean = this.intent.getBooleanExtra(REQUEST_PARAMS.INCLUDE_REFRESH_TOKEN.name, true)

        val cancelButton = findViewById<Button>(R.id.activity_authorization_cancel_button)
        cancelButton.setOnClickListener {

        }

        val confirmButton = findViewById<Button>(R.id.activity_authorization_confirm_button)
        confirmButton.setOnClickListener {

        }

        val context = this
        val listView = findViewById<ListView>(R.id.activity_authorization_scope_choice_list_view)

        //fetch client
        clientManager.client(clientId) { clientOpt, exception ->

            clientOpt?.let { client ->
                //filter allowed scopes by requested scopes

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