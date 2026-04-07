package com.peter.app.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.peter.app.core.database.dao.AdminSettingsDao
import com.peter.app.core.database.dao.ContactDao
import com.peter.app.core.database.dao.GuardLogDao
import com.peter.app.core.database.dao.BlockedContactDao
import com.peter.app.core.database.dao.WhitelistedAppDao
import com.peter.app.core.database.entity.AdminSettingsEntity
import com.peter.app.core.database.entity.BlockedContactEntity
import com.peter.app.core.database.entity.ContactEntity
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.database.entity.WhitelistedAppEntity

val MIGRATION_2_3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE admin_settings ADD COLUMN isNotificationFilterEnabled INTEGER NOT NULL DEFAULT 1")
        db.execSQL("ALTER TABLE admin_settings ADD COLUMN isConversationScanEnabled INTEGER NOT NULL DEFAULT 1")
        db.execSQL("ALTER TABLE admin_settings ADD COLUMN isCallScreeningEnabled INTEGER NOT NULL DEFAULT 1")
    }
}

val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE admin_settings ADD COLUMN isAutoReplyEnabled INTEGER NOT NULL DEFAULT 0")
    }
}

val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS blocked_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                phoneNumber TEXT NOT NULL,
                displayName TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                blockedAt INTEGER NOT NULL
            )"""
        )
    }
}

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE IF NOT EXISTS guard_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                eventType TEXT NOT NULL,
                packageName TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL
            )"""
        )
    }
}

@Database(
    entities = [
        WhitelistedAppEntity::class,
        ContactEntity::class,
        AdminSettingsEntity::class,
        GuardLogEntity::class,
        BlockedContactEntity::class,
    ],
    version = 5,
    exportSchema = false,
)
abstract class PeterDatabase : RoomDatabase() {
    abstract fun whitelistedAppDao(): WhitelistedAppDao
    abstract fun contactDao(): ContactDao
    abstract fun adminSettingsDao(): AdminSettingsDao
    abstract fun guardLogDao(): GuardLogDao
    abstract fun blockedContactDao(): BlockedContactDao

    companion object {
        @Volatile
        private var INSTANCE: PeterDatabase? = null

        fun getInstance(context: Context): PeterDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    PeterDatabase::class.java,
                    "peter_database",
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
