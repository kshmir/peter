package com.peter.app.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.peter.app.core.database.dao.AdminSettingsDao
import com.peter.app.core.database.dao.ContactDao
import com.peter.app.core.database.dao.WhitelistedAppDao
import com.peter.app.core.database.entity.AdminSettingsEntity
import com.peter.app.core.database.entity.ContactEntity
import com.peter.app.core.database.entity.WhitelistedAppEntity

@Database(
    entities = [
        WhitelistedAppEntity::class,
        ContactEntity::class,
        AdminSettingsEntity::class,
    ],
    version = 1,
    exportSchema = false,
)
abstract class PeterDatabase : RoomDatabase() {
    abstract fun whitelistedAppDao(): WhitelistedAppDao
    abstract fun contactDao(): ContactDao
    abstract fun adminSettingsDao(): AdminSettingsDao

    companion object {
        @Volatile
        private var INSTANCE: PeterDatabase? = null

        fun getInstance(context: Context): PeterDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    PeterDatabase::class.java,
                    "peter_database",
                ).build().also { INSTANCE = it }
            }
        }
    }
}
