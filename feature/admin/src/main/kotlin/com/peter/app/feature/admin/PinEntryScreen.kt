package com.peter.app.feature.admin

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.peter.app.ui.R
import kotlin.math.roundToInt

@Composable
fun PinEntryScreen(
    onPinCorrect: () -> Unit,
    onCancel: () -> Unit,
    isCreatingPin: Boolean = false,
    viewModel: PinEntryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsState()
    val shakeOffset = remember { Animatable(0f) }

    LaunchedEffect(state.isCorrect) {
        if (state.isCorrect) {
            onPinCorrect()
        }
    }

    LaunchedEffect(state.isError) {
        if (state.isError) {
            shakeOffset.animateTo(20f, spring(dampingRatio = 0.3f, stiffness = 800f))
            shakeOffset.animateTo(0f, spring(dampingRatio = 0.3f, stiffness = 800f))
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = if (isCreatingPin) {
                if (state.isConfirming) stringResource(R.string.confirm_pin)
                else stringResource(R.string.create_pin)
            } else {
                stringResource(R.string.enter_pin)
            },
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
        )

        if (isCreatingPin && !state.isConfirming) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.pin_explanation),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        Row(
            modifier = Modifier.offset { IntOffset(shakeOffset.value.roundToInt(), 0) },
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            repeat(4) { index ->
                Box(
                    modifier = Modifier
                        .size(20.dp)
                        .clip(CircleShape)
                        .background(
                            if (index < state.enteredDigits) {
                                if (state.isError) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.outline
                            }
                        ),
                )
            }
        }

        if (state.isError) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = if (state.isLocked) {
                    stringResource(R.string.pin_locked, state.lockSecondsRemaining)
                } else {
                    stringResource(R.string.pin_incorrect)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        val buttons = listOf(
            listOf("1", "2", "3"),
            listOf("4", "5", "6"),
            listOf("7", "8", "9"),
            listOf("", "0", "\u232B"),
        )

        buttons.forEach { row ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly,
            ) {
                row.forEach { label ->
                    if (label.isEmpty()) {
                        Spacer(modifier = Modifier.size(80.dp))
                    } else {
                        NumpadButton(
                            label = label,
                            onClick = {
                                if (label == "\u232B") {
                                    viewModel.onDelete()
                                } else {
                                    if (isCreatingPin) {
                                        viewModel.onDigitEnteredForCreate(label.toInt())
                                    } else {
                                        viewModel.onDigitEntered(label.toInt())
                                    }
                                }
                            },
                            enabled = !state.isLocked,
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
        }

        Spacer(modifier = Modifier.height(16.dp))

        TextButton(onClick = onCancel) {
            Text(
                text = stringResource(R.string.cancel),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
