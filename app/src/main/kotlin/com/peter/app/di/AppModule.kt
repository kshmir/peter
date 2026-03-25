package com.peter.app.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import androidx.room.Room
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.MIGRATION_1_2
import com.peter.app.core.database.dao.AdminSettingsDao
import com.peter.app.core.database.dao.ContactDao
import com.peter.app.core.database.dao.GuardLogDao
import com.peter.app.core.database.dao.WhitelistedAppDao
import com.peter.app.core.repository.AppRepository
import com.peter.app.core.repository.AppRepositoryImpl
import com.peter.app.core.repository.ContactRepository
import com.peter.app.core.repository.ContactRepositoryImpl
import com.peter.app.core.repository.SettingsRepository
import com.peter.app.core.repository.SettingsRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "peter_prefs")

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): PeterDatabase {
        return Room.databaseBuilder(
            context,
            PeterDatabase::class.java,
            "peter_database",
        )
            .addMigrations(MIGRATION_1_2)
            .build()
    }

    @Provides
    fun provideWhitelistedAppDao(db: PeterDatabase): WhitelistedAppDao = db.whitelistedAppDao()

    @Provides
    fun provideContactDao(db: PeterDatabase): ContactDao = db.contactDao()

    @Provides
    fun provideAdminSettingsDao(db: PeterDatabase): AdminSettingsDao = db.adminSettingsDao()

    @Provides
    fun provideGuardLogDao(db: PeterDatabase): GuardLogDao = db.guardLogDao()

    @Provides
    @Singleton
    fun provideDataStore(@ApplicationContext context: Context): DataStore<Preferences> {
        return context.dataStore
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {

    @Binds
    @Singleton
    abstract fun bindAppRepository(impl: AppRepositoryImpl): AppRepository

    @Binds
    @Singleton
    abstract fun bindContactRepository(impl: ContactRepositoryImpl): ContactRepository

    @Binds
    @Singleton
    abstract fun bindSettingsRepository(impl: SettingsRepositoryImpl): SettingsRepository
}
