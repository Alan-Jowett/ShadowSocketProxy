// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct PollBackoff {
    current: Duration,
}

impl PollBackoff {
    pub fn new() -> Self {
        Self {
            current: Duration::from_millis(10),
        }
    }

    pub fn delay(&self) -> Duration {
        self.current
    }

    pub fn reset(&mut self) {
        self.current = Duration::from_millis(10);
    }

    pub fn idle(&mut self) {
        self.current = self
            .current
            .saturating_mul(2)
            .min(Duration::from_millis(250));
    }
}

pub fn accepts_epoch(current: u64, response: u64) -> bool {
    current != 0 && current == response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_backoff_is_bounded_and_resettable() {
        let mut backoff = PollBackoff::new();
        assert_eq!(backoff.delay(), Duration::from_millis(10));
        for _ in 0..8 {
            backoff.idle();
        }
        assert_eq!(backoff.delay(), Duration::from_millis(250));
        backoff.reset();
        assert_eq!(backoff.delay(), Duration::from_millis(10));
    }

    #[test]
    fn epochs_reject_stale_and_zero_values() {
        assert!(!accepts_epoch(0, 0));
        assert!(!accepts_epoch(2, 1));
        assert!(accepts_epoch(2, 2));
    }
}
