package com.verticthub.studio.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val DeepNavyBg = Color(0xFF080D16)
val CharcoalSurface = Color(0xFF0F172A)
val SlateCard = Color(0xFF162033)
val SlateBorder = Color(0xFF26354D)
val ElectricBlue = Color(0xFF38BDF8)
val PrimaryBlue = Color(0xFF2563EB)
val EmeraldReady = Color(0xFF10B981)
val AmberWarn = Color(0xFFF59E0B)
val CrimsonFail = Color(0xFFEF4444)
val TextPrimary = Color(0xFFF1F5F9)
val TextSecondary = Color(0xFF94A3B8)

private val DarkStudioScheme = darkColorScheme(
    primary = ElectricBlue,
    onPrimary = Color(0xFF04121E),
    primaryContainer = PrimaryBlue,
    onPrimaryContainer = Color.White,
    secondary = Color(0xFF60A5FA),
    background = DeepNavyBg,
    onBackground = TextPrimary,
    surface = CharcoalSurface,
    onSurface = TextPrimary,
    surfaceVariant = SlateCard,
    onSurfaceVariant = TextSecondary,
    outline = SlateBorder,
    error = CrimsonFail
)

@Composable
fun VertictHubTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkStudioScheme,
        typography = StudioTypography,
        content = content
    )
}
