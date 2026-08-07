// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::collections::VecDeque;
use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub sequence: u64,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LogError {
    #[error("log cursor {cursor} is older than retained sequence {oldest}")]
    CursorExpired { cursor: u64, oldest: u64 },
}

struct State {
    capacity: usize,
    next_sequence: u64,
    records: VecDeque<LogRecord>,
}

pub struct LogRing {
    state: Mutex<State>,
}

impl LogRing {
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

    pub fn set_capacity(&self, capacity: usize) {
        let mut state = self.state.lock().unwrap();
        state.capacity = capacity.max(1);
        while state.records.len() > state.capacity {
            state.records.pop_front();
        }
    }

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
