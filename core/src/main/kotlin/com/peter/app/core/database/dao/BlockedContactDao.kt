package com.peter.app.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.peter.app.core.database.entity.BlockedContactEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface BlockedContactDao {
    @Query("SELECT * FROM blocked_contacts ORDER BY blockedAt DESC")
    fun getAll(): Flow<List<BlockedContactEntity>>

    @Query("SELECT * FROM blocked_contacts")
    suspend fun getAllSync(): List<BlockedContactEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(contact: BlockedContactEntity)

    @Query("DELETE FROM blocked_contacts WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Delete
    suspend fun delete(contact: BlockedContactEntity)
}
