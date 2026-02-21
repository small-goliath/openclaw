-- Migration: 003_add_performance_indexes.sql
-- Description: Add performance indexes for query optimization (PERF-011)
-- Target: 50% query speed improvement
-- Created: 2026-02-21

-- ============================================================================
-- Performance Optimization Indexes
-- Issue: PERF-011 - Missing database indexes causing slow queries
-- Goal: 50% query speed improvement
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Composite index for (path, source) lookups
-- Use case: File lookups by path within specific source context
-- Expected improvement: 50% faster path-based queries
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_chunks_path_source ON chunks(path, source);

-- ----------------------------------------------------------------------------
-- 2. Session tracking columns and index
-- Use case: Session-scoped memory queries
-- ----------------------------------------------------------------------------
ALTER TABLE chunks ADD COLUMN session_id TEXT;
ALTER TABLE files ADD COLUMN session_id TEXT;

CREATE INDEX IF NOT EXISTS idx_chunks_session_id ON chunks(session_id);
CREATE INDEX IF NOT EXISTS idx_files_session_id ON files(session_id);

-- ----------------------------------------------------------------------------
-- 3. Timestamp index for time-range queries
-- Use case: Time-based filtering (e.g., recent memories, cleanup operations)
-- ----------------------------------------------------------------------------
-- Note: updated_at already exists in chunks table
CREATE INDEX IF NOT EXISTS idx_chunks_updated_at ON chunks(updated_at);
CREATE INDEX IF NOT EXISTS idx_files_mtime ON files(mtime);

-- Composite index for time-range queries with source filtering
CREATE INDEX IF NOT EXISTS idx_chunks_updated_at_source ON chunks(updated_at, source);

-- ----------------------------------------------------------------------------
-- 4. User tracking columns and index
-- Use case: User-scoped queries for multi-user environments
-- ----------------------------------------------------------------------------
ALTER TABLE chunks ADD COLUMN user_id TEXT;
ALTER TABLE files ADD COLUMN user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_chunks_user_id ON chunks(user_id);
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);

-- Composite index for user + time queries
CREATE INDEX IF NOT EXISTS idx_chunks_user_id_updated_at ON chunks(user_id, updated_at);

-- ----------------------------------------------------------------------------
-- 5. Agent tracking columns and index
-- Use case: Agent-scoped queries for multi-agent environments
-- ----------------------------------------------------------------------------
ALTER TABLE chunks ADD COLUMN agent_id TEXT;
ALTER TABLE files ADD COLUMN agent_id TEXT;

CREATE INDEX IF NOT EXISTS idx_chunks_agent_id ON chunks(agent_id);
CREATE INDEX IF NOT EXISTS idx_files_agent_id ON files(agent_id);

-- Composite index for agent + time queries
CREATE INDEX IF NOT EXISTS idx_chunks_agent_id_updated_at ON chunks(agent_id, updated_at);

-- ----------------------------------------------------------------------------
-- 6. Additional optimization indexes
-- ----------------------------------------------------------------------------

-- Hash-based lookups for deduplication
CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(hash);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);

-- Model-based filtering (for embeddings management)
CREATE INDEX IF NOT EXISTS idx_chunks_model ON chunks(model);

-- Source-based aggregation queries
CREATE INDEX IF NOT EXISTS idx_files_source ON files(source);

-- ----------------------------------------------------------------------------
-- 7. Index usage monitoring setup
-- SQLite provides index usage stats via sqlite_stat1 table after ANALYZE
-- ----------------------------------------------------------------------------

-- Run ANALYZE to update statistics for query planner
ANALYZE;

-- ----------------------------------------------------------------------------
-- Index Summary
-- ----------------------------------------------------------------------------
-- New indexes created:
--   - idx_chunks_path_source: Composite (path, source)
--   - idx_chunks_session_id: Session-scoped queries
--   - idx_files_session_id: Session-scoped file queries
--   - idx_chunks_updated_at: Time-range queries
--   - idx_files_mtime: File modification time queries
--   - idx_chunks_updated_at_source: Time + source composite
--   - idx_chunks_user_id: User-scoped queries
--   - idx_files_user_id: User-scoped file queries
--   - idx_chunks_user_id_updated_at: User + time composite
--   - idx_chunks_agent_id: Agent-scoped queries
--   - idx_files_agent_id: Agent-scoped file queries
--   - idx_chunks_agent_id_updated_at: Agent + time composite
--   - idx_chunks_hash: Hash-based deduplication
--   - idx_files_hash: File hash lookups
--   - idx_chunks_model: Model filtering
--   - idx_files_source: Source aggregation
--
-- New columns added:
--   - chunks.session_id: Session tracking
--   - files.session_id: Session tracking
--   - chunks.user_id: User tracking
--   - files.user_id: User tracking
--   - chunks.agent_id: Agent tracking
--   - files.agent_id: Agent tracking
-- ----------------------------------------------------------------------------

-- Verify indexes were created
SELECT name, sql FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%';
