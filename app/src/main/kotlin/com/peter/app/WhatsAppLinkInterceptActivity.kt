package com.peter.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.util.LinkClassification
import com.peter.app.core.util.WhatsAppLinkClassifier
import com.peter.app.ui.R
import com.peter.app.ui.theme.PeterTheme
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@AndroidEntryPoint
class WhatsAppLinkInterceptActivity : ComponentActivity() {

    companion object {
        private const val TAG = "LinkGuard"
        private const val WHATSAPP_PACKAGE = "com.whatsapp"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uri = intent?.data
        if (uri == null) {
            finish()
            return
        }

        Log.d(TAG, "Intercepted link: $uri")

        val db = PeterDatabase.getInstance(this)
        CoroutineScope(Dispatchers.IO).launch {
            val knownPhones = db.contactDao().getAll()
                .let { flow ->
                    // Collect first emission to get current contacts
                    var phones = emptySet<String>()
                    val job = launch {
                        flow.collect { contacts ->
                            phones = contacts.map { it.phoneNumber }.toSet()
                        }
                    }
                    // Give it a moment to emit, then cancel
                    kotlinx.coroutines.delay(100)
                    job.cancel()
                    phones
                }

            val classification = WhatsAppLinkClassifier.classify(uri, knownPhones)

            launch(Dispatchers.Main) {
                when (classification) {
                    LinkClassification.SAFE -> {
                        forwardToWhatsApp(uri)
                    }
                    LinkClassification.GROUP_INVITE,
                    LinkClassification.UNKNOWN_CONTACT -> {
                        showBlockDialog(uri, classification)
                        logEvent(db, uri, classification)
                    }
                }
            }
        }
    }

    private fun showBlockDialog(uri: Uri, classification: LinkClassification) {
        setContent {
            PeterTheme {
                LinkBlockDialog(
                    classification = classification,
                    uri = uri,
                    onAllow = {
                        forwardToWhatsApp(uri)
                    },
                    onBlock = {
                        finish()
                    },
                )
            }
        }
    }

    private fun forwardToWhatsApp(uri: Uri) {
        try {
            val forward = Intent(Intent.ACTION_VIEW, uri).apply {
                setPackage(WHATSAPP_PACKAGE)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(forward)
        } catch (e: Exception) {
            Log.e(TAG, "Cannot forward to WhatsApp", e)
        }
        finish()
    }

    private fun logEvent(db: PeterDatabase, uri: Uri, classification: LinkClassification) {
        CoroutineScope(Dispatchers.IO).launch {
            db.guardLogDao().insert(
                GuardLogEntity(
                    eventType = "LINK_BLOCKED",
                    packageName = "whatsapp",
                    detail = "$classification: $uri",
                )
            )
        }
    }
}

@Composable
private fun LinkBlockDialog(
    classification: LinkClassification,
    uri: Uri,
    onAllow: () -> Unit,
    onBlock: () -> Unit,
) {
    Dialog(onDismissRequest = onBlock) {
        Card {
            Column(modifier = Modifier.padding(24.dp)) {
                Text(
                    text = if (classification == LinkClassification.GROUP_INVITE) {
                        stringResource(R.string.link_guard_group_title)
                    } else {
                        stringResource(R.string.link_guard_unknown_title)
                    },
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = if (classification == LinkClassification.GROUP_INVITE) {
                        stringResource(R.string.link_guard_group_message)
                    } else {
                        stringResource(R.string.link_guard_unknown_message)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(24.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    OutlinedButton(onClick = onAllow) {
                        Text(stringResource(R.string.link_guard_allow))
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Button(onClick = onBlock) {
                        Text(stringResource(R.string.link_guard_block))
                    }
                }
            }
        }
    }
}
