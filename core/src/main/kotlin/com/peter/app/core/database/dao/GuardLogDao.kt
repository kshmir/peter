package com.peter.app.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.peter.app.core.database.entity.GuardLogEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface GuardLogDao {
    @Insert
    suspend fun insert(entry: GuardLogEntity)

    @Query("SELECT * FROM guard_log ORDER BY timestamp DESC")
    fun getAll(): Flow<List<GuardLogEntity>>

    @Query("SELECT * FROM guard_log ORDER BY timestamp DESC LIMIT :limit")
    fun getRecent(limit: Int): Flow<List<GuardLogEntity>>

    @Query("DELETE FROM guard_log WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)
}
