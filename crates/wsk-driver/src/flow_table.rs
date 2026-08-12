// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Host-independent bounded flow-table state and identity tracking.

use crate::abi::{Generation, MappingTuple, RequestId};

/// Maximum number of simultaneous TCP flows and UDP associations.
pub const FLOW_TABLE_CAPACITY: usize = 64;

/// Exact identity used to reuse UDP associations without merging clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    /// Synthetic tuple observed by the listener.
    pub synthetic: MappingTuple,
    /// Original client sockaddr bytes, including the family-specific layout.
    pub client: [u8; 28],
    /// Number of meaningful bytes in `client`.
    pub client_len: u8,
}

impl FlowKey {
    /// Creates a key for a TCP flow, which is uniquely identified by its tuple.
    pub const fn tcp(synthetic: MappingTuple) -> Self {
        Self {
            synthetic,
            client: [0; 28],
            client_len: 0,
        }
    }

    /// Creates a key for a UDP association.
    pub const fn udp(synthetic: MappingTuple, client: [u8; 28], client_len: u8) -> Self {
        Self {
            synthetic,
            client,
            client_len,
        }
    }
}

/// Lifecycle state tracked independently of WSK socket ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// A mapping request was published and awaits broker completion.
    AwaitingMapping,
    /// The broker completion is validated and the outbound socket is opening.
    Completing,
    /// The original socket exists and forwarding is enabled.
    Mapped,
    /// Socket close is in progress and the slot remains reserved.
    Closing,
}

/// One table entry and its request correlation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEntry {
    /// Exact flow identity.
    pub key: FlowKey,
    /// Current lifecycle state.
    pub state: FlowState,
    /// Broker request identity.
    pub request_id: RequestId,
    /// Broker request generation.
    pub generation: Generation,
    /// Mapping or idle-cleanup deadline in 100-ns units.
    pub deadline: u64,
}

/// Result of reserving a flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveResult {
    /// A new slot was allocated.
    New(usize),
    /// The exact key already has an active association.
    Existing(usize),
    /// No bounded slot is available.
    Full,
}

/// Fixed-size, allocation-free flow table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTable<const N: usize> {
    entries: [Option<FlowEntry>; N],
}

impl<const N: usize> FlowTable<N> {
    /// Creates an empty table.
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Returns the entry at an index, if it is still allocated.
    pub const fn get(&self, index: usize) -> Option<FlowEntry> {
        if index < N {
            self.entries[index]
        } else {
            None
        }
    }

    /// Finds an exact active key.
    pub fn find(&self, key: FlowKey) -> Option<usize> {
        let mut index = 0;
        while index < N {
            if let Some(entry) = self.entries[index] {
                if entry.key == key {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    /// Reserves a new key or returns its existing association.
    pub fn reserve(
        &mut self,
        key: FlowKey,
        request_id: RequestId,
        generation: Generation,
        deadline: u64,
    ) -> ReserveResult {
        if let Some(index) = self.find(key) {
            return ReserveResult::Existing(index);
        }
        let mut index = 0;
        while index < N {
            if self.entries[index].is_none() {
                self.entries[index] = Some(FlowEntry {
                    key,
                    state: FlowState::AwaitingMapping,
                    request_id,
                    generation,
                    deadline,
                });
                return ReserveResult::New(index);
            }
            index += 1;
        }
        ReserveResult::Full
    }

    /// Changes an awaiting entry to mapped if its identity is current.
    pub fn mark_completing(
        &mut self,
        index: usize,
        request_id: RequestId,
        generation: Generation,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            return false;
        };
        if entry.state != FlowState::AwaitingMapping
            || entry.request_id != request_id
            || entry.generation != generation
        {
            return false;
        }
        entry.state = FlowState::Completing;
        entry.deadline = 0;
        true
    }

    /// Changes a completing entry to mapped if its identity is current.
    pub fn mark_mapped(
        &mut self,
        index: usize,
        request_id: RequestId,
        generation: Generation,
        deadline: u64,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            return false;
        };
        if entry.state != FlowState::Completing
            || entry.request_id != request_id
            || entry.generation != generation
        {
            return false;
        }
        entry.state = FlowState::Mapped;
        entry.deadline = deadline;
        true
    }

    /// Refreshes a mapped flow's idle deadline.
    pub fn touch(&mut self, index: usize, deadline: u64) -> bool {
        let Some(entry) = self.entries.get_mut(index).and_then(Option::as_mut) else {
            return false;
        };
        if entry.state != FlowState::Mapped {
            return false;
        }
        entry.deadline = deadline;
        true
    }

    /// Marks a flow closing while retaining its slot until close completion.
    pub fn mark_closing(&mut self, index: usize) -> Option<FlowEntry> {
        let entry = self.entries.get_mut(index).and_then(Option::as_mut)?;
        if entry.state == FlowState::Closing {
            return Some(*entry);
        }
        entry.state = FlowState::Closing;
        entry.deadline = 0;
        Some(*entry)
    }

    /// Releases a slot after all owned asynchronous resources are closed.
    pub fn release(&mut self, index: usize) -> Option<FlowEntry> {
        if index >= N {
            return None;
        }
        self.entries[index].take()
    }

    /// Returns whether an entry is stale at the supplied clock value.
    pub fn is_expired(&self, index: usize, now: u64) -> bool {
        self.get(index)
            .map(|entry| entry.deadline != 0 && now >= entry.deadline)
            .unwrap_or(false)
    }
}

impl<const N: usize> Default for FlowTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(protocol: u8, source_port: u16) -> MappingTuple {
        MappingTuple {
            protocol,
            address_family: 4,
            reserved: 0,
            source_port,
            destination_port: 15_000,
            source_address: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination_address: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn enforces_capacity_and_reuses_exact_udp_key() {
        let mut table = FlowTable::<2>::new();
        let first = FlowKey::udp(tuple(17, 1000), [1; 28], 16);
        let second = FlowKey::udp(tuple(17, 1001), [2; 28], 16);
        assert_eq!(
            table.reserve(first, RequestId(1), Generation(1), 10),
            ReserveResult::New(0)
        );
        assert_eq!(
            table.reserve(first, RequestId(2), Generation(2), 20),
            ReserveResult::Existing(0)
        );
        assert_eq!(
            table.reserve(second, RequestId(3), Generation(3), 30),
            ReserveResult::New(1)
        );
        assert_eq!(
            table.reserve(
                FlowKey::tcp(tuple(6, 1002)),
                RequestId(4),
                Generation(4),
                40
            ),
            ReserveResult::Full
        );
    }

    #[test]
    fn correlates_generation_and_cleans_stale_mapped_entry() {
        let mut table = FlowTable::<1>::new();
        let key = FlowKey::tcp(tuple(6, 2000));
        assert_eq!(
            table.reserve(key, RequestId(7), Generation(9), 100),
            ReserveResult::New(0)
        );
        assert!(!table.mark_mapped(0, RequestId(7), Generation(8), 200));
        assert!(table.mark_completing(0, RequestId(7), Generation(9)));
        assert!(table.mark_mapped(0, RequestId(7), Generation(9), 200));
        assert!(!table.is_expired(0, 199));
        assert!(table.is_expired(0, 200));
        assert_eq!(table.mark_closing(0).unwrap().state, FlowState::Closing);
        assert!(table.release(0).is_some());
        assert!(table.get(0).is_none());
    }
}
