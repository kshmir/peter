package com.peter.app.core.util

/**
 * Groups related Android packages so that whitelisting one allows all in the group.
 *
 * Example: Whitelisting Chrome (com.android.chrome) also allows the Google Search
 * widget (com.google.android.googlequicksearchbox) because they are in the same group.
 */
object PackageGroupResolver {

    private val PACKAGE_GROUPS: List<Set<String>> = listOf(
        // Browser + Search
        setOf(
            "com.android.chrome",
            "com.google.android.googlequicksearchbox",
            "com.google.android.gms",
            "com.google.android.websearch",
            "com.google.android.apps.searchlite",
        ),
        // WhatsApp
        setOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
        ),
        // Phone / Dialer
        setOf(
            "com.google.android.dialer",
            "com.android.dialer",
            "com.android.phone",
            "com.android.server.telecom",
            "com.android.incallui",
            "com.samsung.android.dialer",
            "com.samsung.android.incallui",
        ),
        // Camera / Gallery
        setOf(
            "com.google.android.GoogleCamera",
            "com.android.camera",
            "com.android.camera2",
            "com.samsung.android.camera",
            "com.google.android.apps.photos",
            "com.samsung.android.gallery",
        ),
        // YouTube (search within YouTube can trigger Google activities)
        setOf(
            "com.google.android.youtube",
            "com.google.android.youtube.tv",
        ),
        // Messages / SMS
        setOf(
            "com.google.android.apps.messaging",
            "com.android.mms",
            "com.samsung.android.messaging",
        ),
    )

    /** Reverse index: package name → group index for O(1) lookup */
    private val packageToGroupIndex: Map<String, Int> = buildMap {
        PACKAGE_GROUPS.forEachIndexed { index, group ->
            group.forEach { pkg -> put(pkg, index) }
        }
    }

    /**
     * Check if [packageName] should be allowed given the current [whitelistedPackages].
     * Returns true if:
     * - The package is directly whitelisted, OR
     * - The package belongs to a group where at least one member is whitelisted
     */
    fun isAllowed(packageName: String, whitelistedPackages: Set<String>): Boolean {
        if (packageName in whitelistedPackages) return true

        val groupIndex = packageToGroupIndex[packageName] ?: return false
        val group = PACKAGE_GROUPS[groupIndex]
        return group.any { it in whitelistedPackages }
    }

    /**
     * Expand a set of whitelisted packages to include all group members.
     * Useful for pre-computing the full allowed set.
     */
    fun expandWhitelist(whitelistedPackages: Set<String>): Set<String> {
        val expanded = whitelistedPackages.toMutableSet()
        for (pkg in whitelistedPackages) {
            val groupIndex = packageToGroupIndex[pkg] ?: continue
            expanded.addAll(PACKAGE_GROUPS[groupIndex])
        }
        return expanded
    }
}
