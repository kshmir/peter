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
import com.peter.app.core.database.dao.WhitelistedAppDao
import com.peter.app.core.database.entity.AdminSettingsEntity
import com.peter.app.core.database.entity.ContactEntity
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.database.entity.WhitelistedAppEntity

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
    ],
    version = 2,
    exportSchema = false,
)
abstract class PeterDatabase : RoomDatabase() {
    abstract fun whitelistedAppDao(): WhitelistedAppDao
    abstract fun contactDao(): ContactDao
    abstract fun adminSettingsDao(): AdminSettingsDao
    abstract fun guardLogDao(): GuardLogDao

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
                    .addMigrations(MIGRATION_1_2)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
