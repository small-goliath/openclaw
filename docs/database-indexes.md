# Database Index Strategy

## Overview

This document describes the database indexing strategy for OpenClaw's memory system to achieve optimal query performance.

**Issue:** PERF-011 - Missing database indexes causing slow queries
**Goal:** 50% query speed improvement
**Status:** Implemented

---

## Index Summary

### Core Indexes

| Index Name                     | Table  | Columns            | Purpose                 | Expected Improvement |
| ------------------------------ | ------ | ------------------ | ----------------------- | -------------------- |
| `idx_chunks_path`              | chunks | path               | Basic path lookups      | Baseline             |
| `idx_chunks_source`            | chunks | source             | Source filtering        | Baseline             |
| `idx_chunks_path_source`       | chunks | path, source       | Composite lookups       | 50% faster           |
| `idx_chunks_session_id`        | chunks | session_id         | Session-scoped queries  | Fast filtering       |
| `idx_files_session_id`         | files  | session_id         | Session file queries    | Fast filtering       |
| `idx_chunks_updated_at`        | chunks | updated_at         | Time-range queries      | Fast time filtering  |
| `idx_files_mtime`              | files  | mtime              | File modification time  | Fast time filtering  |
| `idx_chunks_updated_at_source` | chunks | updated_at, source | Time + source composite | Optimized reports    |

### User & Agent Scoped Indexes

| Index Name                       | Table  | Columns              | Purpose              |
| -------------------------------- | ------ | -------------------- | -------------------- |
| `idx_chunks_user_id`             | chunks | user_id              | User-scoped queries  |
| `idx_files_user_id`              | files  | user_id              | User file queries    |
| `idx_chunks_user_id_updated_at`  | chunks | user_id, updated_at  | User + time queries  |
| `idx_chunks_agent_id`            | chunks | agent_id             | Agent-scoped queries |
| `idx_files_agent_id`             | files  | agent_id             | Agent file queries   |
| `idx_chunks_agent_id_updated_at` | chunks | agent_id, updated_at | Agent + time queries |

### Optimization Indexes

| Index Name                       | Table           | Columns    | Purpose                  |
| -------------------------------- | --------------- | ---------- | ------------------------ |
| `idx_chunks_hash`                | chunks          | hash       | Hash-based deduplication |
| `idx_files_hash`                 | files           | hash       | File hash lookups        |
| `idx_chunks_model`               | chunks          | model      | Model filtering          |
| `idx_files_source`               | files           | source     | Source aggregation       |
| `idx_embedding_cache_updated_at` | embedding_cache | updated_at | Cache cleanup            |

---

## Query Patterns

### 1. Path + Source Lookup (Primary)

```sql
-- Uses: idx_chunks_path_source
SELECT * FROM chunks WHERE path = ? AND source = 'memory';
```

**Use Case:** Retrieve all chunks for a specific file within a source context.

### 2. Session-Scoped Queries

```sql
-- Uses: idx_chunks_session_id
SELECT * FROM chunks WHERE session_id = ?;

-- Uses: idx_chunks_session_id + idx_chunks_updated_at (composite)
SELECT * FROM chunks WHERE session_id = ? AND updated_at > ?;
```

**Use Case:** Session-based memory retrieval and cleanup.

### 3. Time-Range Queries

```sql
-- Uses: idx_chunks_updated_at
SELECT * FROM chunks WHERE updated_at > ?;

-- Uses: idx_chunks_updated_at_source
SELECT * FROM chunks WHERE updated_at > ? AND source = ?;
```

**Use Case:** Recent memories, data retention policies, cleanup operations.

### 4. User-Scoped Queries

```sql
-- Uses: idx_chunks_user_id
SELECT * FROM chunks WHERE user_id = ?;

-- Uses: idx_chunks_user_id_updated_at
SELECT * FROM chunks WHERE user_id = ? AND updated_at > ?;
```

**Use Case:** Multi-user environments, user-specific memory retrieval.

### 5. Agent-Scoped Queries

```sql
-- Uses: idx_chunks_agent_id
SELECT * FROM chunks WHERE agent_id = ?;

-- Uses: idx_chunks_agent_id_updated_at
SELECT * FROM chunks WHERE agent_id = ? AND updated_at > ?;
```

**Use Case:** Multi-agent environments, agent-specific memory retrieval.

---

## Monitoring

### Index Effectiveness Verification

Use the built-in monitoring functions to verify index usage:

```typescript
import { monitorIndexEffectiveness, logIndexEffectivenessReport } from "./memory-schema";

// Get detailed report
const results = monitorIndexEffectiveness(db);
console.log(results);

// Log to subsystem logger
logIndexEffectivenessReport(db);
```

### Query Plan Analysis

Analyze specific queries to verify index usage:

```typescript
import { analyzeQueryPlan, isQueryUsingIndex } from "./memory-schema";

// Get query plan
const plan = analyzeQueryPlan(db, "SELECT * FROM chunks WHERE path = ?", ["/test/path"]);
console.log(plan);

// Check if using index
const usesIndex = isQueryUsingIndex(db, "SELECT * FROM chunks WHERE path = ?", ["/test/path"]);
console.log("Uses index:", usesIndex);
```

### Update Statistics

Run ANALYZE periodically to update query planner statistics:

```typescript
import { updateQueryStats } from "./memory-schema";

updateQueryStats(db);
```

---

## Migration

### Applying Indexes

The migration script is located at:

- `migrations/003_add_performance_indexes.sql`

To apply manually:

```bash
sqlite3 memory.db < migrations/003_add_performance_indexes.sql
```

### Schema Updates

The indexes are automatically created when the memory schema is initialized via `ensureMemoryIndexSchema()`.

---

## Performance Considerations

### Trade-offs

1. **Write Performance:** Each index adds overhead to INSERT/UPDATE/DELETE operations
2. **Storage:** Indexes consume additional disk space
3. **Maintenance:** Indexes require periodic optimization (ANALYZE)

### Best Practices

1. **Query First:** Always verify query patterns before adding indexes
2. **Composite Order:** Put most selective columns first in composite indexes
3. **Covering Indexes:** Include all queried columns when possible
4. **Monitor:** Regularly check index usage and effectiveness

### When to Add Indexes

- Query takes >100ms consistently
- Table has >10,000 rows
- Query is executed frequently (>100 times/day)
- EXPLAIN QUERY PLAN shows "SCAN" instead of "SEARCH"

### When NOT to Add Indexes

- Small tables (<1,000 rows)
- Write-heavy tables with rare reads
- Columns with low cardinality (boolean, enum with few values)
- Temporary or scratch tables

---

## Troubleshooting

### Query Not Using Index

1. Check if ANALYZE has been run recently
2. Verify column types match query parameters
3. Check for type coercion issues
4. Consider forcing index with INDEXED BY (SQLite-specific)

### Slow Queries Despite Indexes

1. Check for full table scans in EXPLAIN output
2. Verify statistics are up to date (ANALYZE)
3. Consider covering indexes for frequently queried columns
4. Check for OR conditions that prevent index usage

### Index Bloat

SQLite automatically manages index bloat, but for large databases:

```sql
-- Rebuild database (vacuum)
VACUUM;

-- Reanalyze
ANALYZE;
```

---

## References

- [SQLite Query Planner](https://www.sqlite.org/queryplanner.html)
- [SQLite Indexing](https://www.sqlite.org/lang_createindex.html)
- [EXPLAIN QUERY PLAN](https://www.sqlite.org/eqp.html)
- Security Report: `security/security.md` Section 5.3
