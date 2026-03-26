package com.peter.app.feature.admin

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PhoneDisabled
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.peter.app.ui.R

enum class ThreatLevel {
    UNKNOWN,
    WARNING,
    HIGH_ALERT,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationGuardDemoScreen(
    onBack: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        TopAppBar(
            title = {
                Text(
                    "Filtro de notificaciones",
                    style = MaterialTheme.typography.titleLarge,
                )
            },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.back),
                        modifier = Modifier.size(32.dp),
                    )
                }
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Vista previa del interceptor",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // State 1: Unknown contact (not registered)
            NotificationInterceptCard(
                phoneNumber = "+54 9 11 5555-1234",
                message = "Hola! Soy María del banco, necesito confirmar tus datos para una transferencia pendiente.",
                profileInitial = "M",
                threatLevel = ThreatLevel.UNKNOWN,
                threatLabel = "Contacto desconocido",
                threatDescription = "Este número no está en tus contactos.",
            )

            // State 2: Warning (reported number)
            NotificationInterceptCard(
                phoneNumber = "+1 (555) 987-6543",
                message = "Congratulations! You've been selected for a special prize. Click here to claim: bit.ly/xyz",
                profileInitial = "?",
                threatLevel = ThreatLevel.WARNING,
                threatLabel = "Número reportado",
                threatDescription = "Al menos 1 persona reportó este número como sospechoso.",
            )

            // State 3: High alert (scam keywords)
            NotificationInterceptCard(
                phoneNumber = "+55 11 9999-0000",
                message = "URGENTE: Tu cuenta de WhatsApp será suspendida en 24 horas. Verifica tu identidad ahora: wa.me/verify",
                profileInitial = "!",
                threatLevel = ThreatLevel.HIGH_ALERT,
                threatLabel = "Alerta de estafa",
                threatDescription = "Mensaje contiene patrones de estafa: \"cuenta suspendida\", \"verificar identidad\".",
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Así se vería cuando un mensaje de WhatsApp es interceptado. El usuario decide si lo permite o lo bloquea.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(32.dp))

            // ── PHONE CALL SECTION ──
            Text(
                text = "Filtro de llamadas",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Vista previa del interceptor de llamadas",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Call State 1: Unknown caller
            CallInterceptCard(
                phoneNumber = "+54 9 11 4444-8888",
                callerInfo = "Buenos Aires, Argentina",
                profileInitial = "?",
                threatLevel = ThreatLevel.UNKNOWN,
                threatLabel = "Llamada desconocida",
                threatDescription = "Este número no está en tus contactos.",
            )

            // Call State 2: Reported number
            CallInterceptCard(
                phoneNumber = "+1 (800) 555-0199",
                callerInfo = "Estados Unidos — Llamadas frecuentes reportadas",
                profileInitial = "!",
                threatLevel = ThreatLevel.WARNING,
                threatLabel = "Número reportado",
                threatDescription = "12 personas reportaron este número como spam telefónico.",
            )

            // Call State 3: High alert scam call
            CallInterceptCard(
                phoneNumber = "+44 20 7946 0958",
                callerInfo = "Reino Unido — Patrón de estafa detectado",
                profileInitial = "!",
                threatLevel = ThreatLevel.HIGH_ALERT,
                threatLabel = "Estafa telefónica",
                threatDescription = "Número asociado con estafas de soporte técnico. Llamada bloqueada automáticamente.",
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Las llamadas de contactos conocidos entran normalmente. Las desconocidas se filtran según el nivel de riesgo.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun NotificationInterceptCard(
    phoneNumber: String,
    message: String,
    profileInitial: String,
    threatLevel: ThreatLevel,
    threatLabel: String,
    threatDescription: String,
) {
    val (borderColor, badgeColor, badgeTextColor) = when (threatLevel) {
        ThreatLevel.UNKNOWN -> Triple(
            Color(0xFFFFB300),
            Color(0xFFFFF3E0),
            Color(0xFFE65100),
        )
        ThreatLevel.WARNING -> Triple(
            Color(0xFFFF9800),
            Color(0xFFFFF3E0),
            Color(0xFFE65100),
        )
        ThreatLevel.HIGH_ALERT -> Triple(
            Color(0xFFF44336),
            Color(0xFFFFEBEE),
            Color(0xFFC62828),
        )
    }

    val avatarColor = when (threatLevel) {
        ThreatLevel.UNKNOWN -> Color(0xFFFFB300)
        ThreatLevel.WARNING -> Color(0xFFFF9800)
        ThreatLevel.HIGH_ALERT -> Color(0xFFF44336)
    }

    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        shape = RoundedCornerShape(20.dp),
        border = androidx.compose.foundation.BorderStroke(2.dp, borderColor),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
        ) {
            // Threat badge
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(badgeColor)
                    .padding(horizontal = 12.dp, vertical = 4.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = badgeTextColor,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = threatLabel,
                        style = MaterialTheme.typography.labelMedium,
                        color = badgeTextColor,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Sender row
            Row(
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // Profile picture placeholder
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(avatarColor),
                    contentAlignment = Alignment.Center,
                ) {
                    if (profileInitial == "?") {
                        Icon(
                            Icons.Filled.Person,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(32.dp),
                        )
                    } else {
                        Text(
                            text = profileInitial,
                            color = Color.White,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column {
                    Text(
                        text = phoneNumber,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = threatDescription,
                        style = MaterialTheme.typography.bodySmall,
                        color = badgeTextColor,
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Message preview
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                ),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(16.dp),
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedButton(
                    onClick = {},
                    modifier = Modifier.weight(1f).height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Icon(
                        Icons.Filled.Check,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Permitir", fontWeight = FontWeight.Bold)
                }

                Button(
                    onClick = {},
                    modifier = Modifier.weight(1f).height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = when (threatLevel) {
                            ThreatLevel.UNKNOWN -> Color(0xFFFFB300)
                            ThreatLevel.WARNING -> Color(0xFFFF9800)
                            ThreatLevel.HIGH_ALERT -> Color(0xFFF44336)
                        },
                    ),
                ) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Bloquear",
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                    )
                }
            }
        }
    }
}

@Composable
private fun CallInterceptCard(
    phoneNumber: String,
    callerInfo: String,
    profileInitial: String,
    threatLevel: ThreatLevel,
    threatLabel: String,
    threatDescription: String,
) {
    val (borderColor, badgeColor, badgeTextColor) = when (threatLevel) {
        ThreatLevel.UNKNOWN -> Triple(Color(0xFFFFB300), Color(0xFFFFF3E0), Color(0xFFE65100))
        ThreatLevel.WARNING -> Triple(Color(0xFFFF9800), Color(0xFFFFF3E0), Color(0xFFE65100))
        ThreatLevel.HIGH_ALERT -> Triple(Color(0xFFF44336), Color(0xFFFFEBEE), Color(0xFFC62828))
    }

    val avatarColor = when (threatLevel) {
        ThreatLevel.UNKNOWN -> Color(0xFFFFB300)
        ThreatLevel.WARNING -> Color(0xFFFF9800)
        ThreatLevel.HIGH_ALERT -> Color(0xFFF44336)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(20.dp),
        border = androidx.compose.foundation.BorderStroke(2.dp, borderColor),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
        ) {
            // Threat badge
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(badgeColor)
                    .padding(horizontal = 12.dp, vertical = 4.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (threatLevel == ThreatLevel.HIGH_ALERT) Icons.Filled.PhoneDisabled
                                     else Icons.Filled.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = badgeTextColor,
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = threatLabel,
                        style = MaterialTheme.typography.labelMedium,
                        color = badgeTextColor,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Caller info with large phone icon
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(avatarColor),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Call,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(32.dp),
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column {
                    Text(
                        text = phoneNumber,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = callerInfo,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Threat description
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = badgeColor.copy(alpha = 0.5f),
                ),
                shape = RoundedCornerShape(12.dp),
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        Icons.Filled.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = badgeTextColor,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = threatDescription,
                        style = MaterialTheme.typography.bodySmall,
                        color = badgeTextColor,
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (threatLevel != ThreatLevel.HIGH_ALERT) {
                    OutlinedButton(
                        onClick = {},
                        modifier = Modifier
                            .weight(1f)
                            .height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Icon(Icons.Filled.Call, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Contestar", fontWeight = FontWeight.Bold)
                    }
                }

                Button(
                    onClick = {},
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = borderColor),
                ) {
                    Icon(Icons.Filled.PhoneDisabled, contentDescription = null, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (threatLevel == ThreatLevel.HIGH_ALERT) "Bloqueado" else "Rechazar",
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                    )
                }
            }

            if (threatLevel == ThreatLevel.HIGH_ALERT) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Esta llamada fue bloqueada automáticamente.",
                    style = MaterialTheme.typography.bodySmall,
                    color = badgeTextColor,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                )
            }
        }
    }
}
