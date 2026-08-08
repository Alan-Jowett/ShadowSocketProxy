// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Provides a mutex-protected bounded log ring with monotonic cursors.

use std::collections::VecDeque;
use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
/// One retained service log entry.
pub struct LogRecord {
    /// Monotonic cursor returned by `append`.
    pub sequence: u64,
    /// Caller-supplied severity label such as `INFO` or `ERROR`.
    pub level: String,
    /// Human-readable event text.
    pub message: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Errors returned when a log cursor can no longer be served.
pub enum LogError {
    #[error("log cursor {cursor} is older than retained sequence {oldest}")]
    /// The requested cursor predates the oldest retained record.
    CursorExpired { cursor: u64, oldest: u64 },
}

/// Mutable ring state protected by `LogRing::state`.
struct State {
    /// Maximum number of records retained; always at least one after updates.
    capacity: usize,
    /// Sequence assigned to the next appended record.
    next_sequence: u64,
    /// Oldest-to-newest retained records.
    records: VecDeque<LogRecord>,
}

/// Thread-safe bounded log storage with cursor-based reads.
pub struct LogRing {
    /// Synchronizes appends, retention changes, and pulls.
    state: Mutex<State>,
}

impl LogRing {
    /// Creates an empty ring; zero capacity is rejected.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            state: Mutex::new(State {
                capacity,
                next_sequence: 1,
                records: VecDeque::with_capacity(capacity),
            }),
        }
    }

    /// Appends a record, evicts oldest entries over capacity, and returns its
    /// monotonic sequence number.
    pub fn append(&self, level: impl Into<String>, message: impl Into<String>) -> u64 {
        let mut state = self.state.lock().unwrap();
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.records.push_back(LogRecord {
            sequence,
            level: level.into(),
            message: message.into(),
        });
        while state.records.len() > state.capacity {
            state.records.pop_front();
        }
        sequence
    }

    /// Changes retention capacity, clamping zero to one and evicting excess
    /// oldest records immediately.
    pub fn set_capacity(&self, capacity: usize) {
        let mut state = self.state.lock().unwrap();
        state.capacity = capacity.max(1);
        while state.records.len() > state.capacity {
            state.records.pop_front();
        }
    }

    /// Returns records newer than `cursor` up to `limit` and the cursor of the
    /// last returned record; stale cursors fail with `CursorExpired`.
    pub fn pull(&self, cursor: u64, limit: usize) -> Result<(Vec<LogRecord>, u64), LogError> {
        let state = self.state.lock().unwrap();
        if let Some(oldest) = state.records.front().map(|record| record.sequence) {
            if cursor.saturating_add(1) < oldest {
                return Err(LogError::CursorExpired { cursor, oldest });
            }
        }
        let records = state
            .records
            .iter()
            .filter(|record| record.sequence > cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = records
            .last()
            .map(|record| record.sequence)
            .unwrap_or(cursor);
        Ok((records, next_cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_monotonic_and_expires() {
        let logs = LogRing::new(2);
        logs.append("INFO", "one");
        logs.append("INFO", "two");
        logs.append("INFO", "three");
        assert!(matches!(
            logs.pull(0, 10),
            Err(LogError::CursorExpired { .. })
        ));
        let (records, cursor) = logs.pull(1, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(cursor, 3);
        assert!(logs.pull(cursor, 10).unwrap().0.is_empty());
    }
}
