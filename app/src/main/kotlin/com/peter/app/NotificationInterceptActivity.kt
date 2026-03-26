package com.peter.app

import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.peter.app.core.service.InterceptData
import com.peter.app.ui.theme.PeterTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class NotificationInterceptActivity : ComponentActivity() {

    companion object {
        private const val TAG = "NotifIntercept"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sender = intent.getStringExtra("sender") ?: "Unknown"
        val message = intent.getStringExtra("message") ?: ""
        val phone = intent.getStringExtra("phone")
        val threatLevel = intent.getIntExtra("threat_level", 0)
        val threatLabel = intent.getStringExtra("threat_label") ?: ""
        val threatDesc = intent.getStringExtra("threat_desc") ?: ""
        val status = intent.getStringExtra("status") ?: ""
        val profilePic = InterceptData.pendingProfilePic

        Log.w(TAG, "Intercepting: sender=$sender, threat=$threatLevel, status=$status")

        setContent {
            PeterTheme {
                if (status == "QUARANTINED") {
                    QuarantineScreen(
                        sender = sender,
                        message = message,
                        threatDesc = threatDesc,
                        profilePic = profilePic,
                        onDismiss = {
                            Log.w(TAG, "QUARANTINE dismissed: $sender")
                            finish() // back to WhatsApp chat list (not the scam conversation)
                        },
                    )
                } else {
                    InterceptScreen(
                        sender = sender,
                        message = message,
                        phone = phone,
                        threatLevel = threatLevel,
                        threatLabel = threatLabel,
                        threatDesc = threatDesc,
                        profilePic = profilePic,
                        onAllow = {
                            Log.w(TAG, "ALLOWED: $sender")
                            openWhatsApp()
                            finish()
                        },
                        onBlock = {
                            Log.w(TAG, "BLOCKED: $sender")
                            finish()
                        },
                    )
                }
            }
        }
    }

    private fun goHome() {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        if (intent != null) startActivity(intent)
        finish()
    }

    private fun openWhatsApp() {
        try {
            val intent = packageManager.getLaunchIntentForPackage("com.whatsapp")
            if (intent != null) {
                startActivity(intent)
            }
        } catch (_: Exception) {}
    }

    override fun onDestroy() {
        InterceptData.pendingProfilePic = null
        super.onDestroy()
    }
}

@Composable
private fun InterceptScreen(
    sender: String,
    message: String,
    phone: String?,
    threatLevel: Int,
    threatLabel: String,
    threatDesc: String,
    profilePic: Bitmap?,
    onAllow: () -> Unit,
    onBlock: () -> Unit,
) {
    val borderColor = when (threatLevel) {
        0 -> Color(0xFFFFB300)
        1 -> Color(0xFFFF9800)
        else -> Color(0xFFF44336)
    }
    val badgeColor = when (threatLevel) {
        0 -> Color(0xFFFFF3E0)
        1 -> Color(0xFFFFF3E0)
        else -> Color(0xFFFFEBEE)
    }
    val badgeTextColor = when (threatLevel) {
        0 -> Color(0xFFE65100)
        1 -> Color(0xFFE65100)
        else -> Color(0xFFC62828)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xCC000000)),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            shape = RoundedCornerShape(24.dp),
            border = androidx.compose.foundation.BorderStroke(3.dp, borderColor),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // Threat badge
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .background(badgeColor)
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = badgeTextColor,
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = threatLabel,
                            color = badgeTextColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                // Profile picture
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(CircleShape)
                        .background(borderColor),
                    contentAlignment = Alignment.Center,
                ) {
                    if (profilePic != null) {
                        Image(
                            bitmap = profilePic.asImageBitmap(),
                            contentDescription = sender,
                            modifier = Modifier.size(80.dp).clip(CircleShape),
                        )
                    } else {
                        Icon(
                            Icons.Filled.Person,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(40.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Sender name / phone
                Text(
                    text = sender,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                    color = Color.Black,
                    textAlign = TextAlign.Center,
                )
                if (phone != null && phone != sender) {
                    Text(
                        text = phone,
                        fontSize = 14.sp,
                        color = Color.Gray,
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Threat description
                Text(
                    text = threatDesc,
                    fontSize = 13.sp,
                    color = badgeTextColor,
                    textAlign = TextAlign.Center,
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Message preview
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF5F5F5)),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text(
                        text = message,
                        modifier = Modifier.padding(16.dp).fillMaxWidth(),
                        fontSize = 15.sp,
                        color = Color.DarkGray,
                        maxLines = 4,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedButton(
                        onClick = onAllow,
                        modifier = Modifier.weight(1f).height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Icon(Icons.Filled.Check, null, Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Permitir", fontWeight = FontWeight.Bold, color = Color.Black)
                    }

                    Button(
                        onClick = onBlock,
                        modifier = Modifier.weight(1f).height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = borderColor),
                    ) {
                        Icon(Icons.Filled.Close, null, Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Bloquear", fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
private fun QuarantineScreen(
    sender: String,
    message: String,
    threatDesc: String,
    profilePic: Bitmap?,
    onDismiss: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFC62828)),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Big warning icon
            Icon(
                Icons.Filled.Warning,
                contentDescription = null,
                modifier = Modifier.size(100.dp),
                tint = Color.White,
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "CONTACTO EN CUARENTENA",
                fontSize = 24.sp,
                fontWeight = FontWeight.ExtraBold,
                color = Color.White,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Contact info
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0x33FFFFFF)),
                shape = RoundedCornerShape(16.dp),
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    // Profile pic
                    Box(
                        modifier = Modifier
                            .size(72.dp)
                            .clip(CircleShape)
                            .background(Color(0x55FFFFFF)),
                        contentAlignment = Alignment.Center,
                    ) {
                        if (profilePic != null) {
                            Image(
                                bitmap = profilePic.asImageBitmap(),
                                contentDescription = sender,
                                modifier = Modifier.size(72.dp).clip(CircleShape),
                            )
                        } else {
                            Icon(
                                Icons.Filled.Person,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(36.dp),
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = sender,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        textAlign = TextAlign.Center,
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "Esta conversación fue bloqueada porque contiene patrones de estafa.",
                fontSize = 16.sp,
                color = Color(0xFFFFCDD2),
                textAlign = TextAlign.Center,
                lineHeight = 22.sp,
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Threat details
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0x22000000)),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = threatDesc,
                    modifier = Modifier.padding(16.dp),
                    fontSize = 14.sp,
                    color = Color(0xFFFFCDD2),
                    textAlign = TextAlign.Center,
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Message preview
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0x22000000)),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = "\"${message.take(120)}\"",
                    modifier = Modifier.padding(16.dp),
                    fontSize = 13.sp,
                    color = Color(0xAAFFFFFF),
                    textAlign = TextAlign.Center,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            Text(
                text = "Pida a un familiar que revise este contacto.",
                fontSize = 14.sp,
                color = Color(0xAAFFFFFF),
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.White),
            ) {
                Text(
                    text = "Volver al inicio",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    color = Color(0xFFC62828),
                )
            }
        }
    }
}
