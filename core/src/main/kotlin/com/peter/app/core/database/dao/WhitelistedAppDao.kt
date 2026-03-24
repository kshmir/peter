package com.peter.app.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.peter.app.core.database.entity.WhitelistedAppEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface WhitelistedAppDao {
    @Query("SELECT * FROM whitelisted_apps ORDER BY sortOrder ASC")
    fun getAll(): Flow<List<WhitelistedAppEntity>>

    @Query("SELECT EXISTS(SELECT 1 FROM whitelisted_apps WHERE packageName = :packageName)")
    fun isWhitelisted(packageName: String): Flow<Boolean>

    @Query("SELECT EXISTS(SELECT 1 FROM whitelisted_apps WHERE packageName = :packageName)")
    suspend fun isWhitelistedSync(packageName: String): Boolean

    @Query("SELECT packageName FROM whitelisted_apps")
    suspend fun getAllPackageNames(): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(app: WhitelistedAppEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(apps: List<WhitelistedAppEntity>)

    @Delete
    suspend fun delete(app: WhitelistedAppEntity)

    @Query("DELETE FROM whitelisted_apps WHERE packageName = :packageName")
    suspend fun deleteByPackageName(packageName: String)

    @Query("UPDATE whitelisted_apps SET sortOrder = :sortOrder WHERE packageName = :packageName")
    suspend fun updateSortOrder(packageName: String, sortOrder: Int)
}
