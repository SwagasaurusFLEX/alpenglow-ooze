//! Ooze scheduler — fair ordering via VRF-seeded randomness.
//!
//! Drop-in replacement for GreedyScheduler. Before each scheduling pass,
//! drains the priority queue, runs a VRF shuffle, rewrites each
//! TransactionPriorityId's priority field to a descending counter so
//! the BTreeSet re-sorts in our shuffled order, then runs the standard
//! greedy loop from that reshuffled queue.
//!
//! Priority fees are still paid (validator revenue preserved) but
//! no longer determine ordering. Atomic bundling, sandwich attacks,
//! and sniping all lose reliability. Arbitrage still works.

#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    super::{
        scheduler::{Scheduler, SchedulingSummary},
        scheduler_common::{
            select_thread, SchedulingCommon, TransactionSchedulingError,
            TransactionSchedulingInfo,
        },
        scheduler_error::SchedulerError,
        transaction_priority_id::TransactionPriorityId,
        transaction_state::TransactionState,
        transaction_state_container::StateContainer,
    },
    crate::banking_stage::{
        consumer::TARGET_NUM_TRANSACTIONS_PER_BATCH,
        scheduler_messages::{ConsumeWork, FinishedConsumeWork},
    },
    agave_scheduling_utils::thread_aware_account_locks::{
        ThreadAwareAccountLocks, ThreadId, ThreadSet, TryLockError,
    },
    crossbeam_channel::{Receiver, Sender},
    log::{debug, info},
    ooze_ordering::{commit_hash, VrfOutput},
    rand::{seq::SliceRandom, SeedableRng},
    rand_chacha::ChaCha20Rng,
    solana_cost_model::block_cost_limits::MAX_BLOCK_UNITS,
    solana_keypair::Keypair,
    solana_runtime_transaction::transaction_with_meta::TransactionWithMeta,
    std::{num::Saturating, sync::Arc},
};

#[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
pub(crate) struct OozeSchedulerConfig {
    pub target_scheduled_cus: u64,
    pub max_scanned_transactions_per_scheduling_pass: usize,
    pub target_transactions_per_batch: usize,
}

impl Default for OozeSchedulerConfig {
    fn default() -> Self {
        Self {
            target_scheduled_cus: MAX_BLOCK_UNITS / 4,
            max_scanned_transactions_per_scheduling_pass: 100_000,
            target_transactions_per_batch: TARGET_NUM_TRANSACTIONS_PER_BATCH,
        }
    }
}

pub struct OozeScheduler<Tx: TransactionWithMeta> {
    common: SchedulingCommon<Tx>,
    unschedulables: Vec<TransactionPriorityId>,
    config: OozeSchedulerConfig,
    signing_key: Arc<Keypair>,
    pass_counter: u64,
}

impl<Tx: TransactionWithMeta> OozeScheduler<Tx> {
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    pub(crate) fn new(
        consume_work_senders: Vec<Sender<ConsumeWork<Tx>>>,
        finished_consume_work_receiver: Receiver<FinishedConsumeWork<Tx>>,
        config: OozeSchedulerConfig,
        signing_key: Arc<Keypair>,
    ) -> Self {
        info!("OozeScheduler initialized — fair ordering engaged");
        Self {
            unschedulables: Vec::with_capacity(config.max_scanned_transactions_per_scheduling_pass),
            common: SchedulingCommon::new(
                consume_work_senders,
                finished_consume_work_receiver,
                config.target_transactions_per_batch,
            ),
            config,
            signing_key,
            pass_counter: 0,
        }
    }

    /// Drain the priority queue, VRF-shuffle the IDs, rewrite priorities
    /// so the BTreeSet sorts in shuffled order, and push back.
    fn apply_ooze_ordering<S: StateContainer<Tx>>(&mut self, container: &mut S) {
        let mut drained: Vec<TransactionPriorityId> = Vec::new();
        while let Some(id) = container.pop() {
            // Only re-circulate transactions that still hold their Tx.
            // Ids whose Tx was already taken (scheduled/in-flight) must not
            // be shuffled back into the schedulable queue.
            if let Some(state) = container.get_mut_transaction_state(id.id) {
                if state.has_transaction() {
                    drained.push(id);
                }
            }
        }

        if drained.len() < 2 {
            container.push_ids_into_queue(drained.into_iter());
            return;
        }

        // Commit over tx IDs. IDs are stable within a scheduling pass.
        let id_bytes: Vec<[u8; 8]> = drained.iter().map(|p| p.id.to_le_bytes()).collect();
        let id_refs: Vec<&[u8]> = id_bytes.iter().map(|b| b.as_ref()).collect();
        let commit = commit_hash(&id_refs);

        self.pass_counter = self.pass_counter.wrapping_add(1);
        let vrf = VrfOutput::evaluate(&self.signing_key, self.pass_counter, commit);

        let mut rng = ChaCha20Rng::from_seed(vrf.randomness);
        drained.shuffle(&mut rng);

        // Rewrite priorities: position 0 gets the highest new priority,
        // so the BTreeSet pops it first.
        let n = drained.len();
        let reordered: Vec<TransactionPriorityId> = drained
            .into_iter()
            .enumerate()
            .map(|(idx, p)| TransactionPriorityId {
                priority: (n - idx) as u64,
                id: p.id,
            })
            .collect();

        debug!(
            "OozeScheduler pass {}: shuffled {} txs (vrf pubkey prefix {:02x}{:02x})",
            self.pass_counter,
            reordered.len(),
            vrf.pubkey[0],
            vrf.pubkey[1]
        );

        container.push_ids_into_queue(reordered.into_iter());
    }
}

impl<Tx: TransactionWithMeta> Scheduler<Tx> for OozeScheduler<Tx> {
    fn schedule<S: StateContainer<Tx>>(
        &mut self,
        container: &mut S,
        budget: u64,
    ) -> Result<SchedulingSummary, SchedulerError> {
        // THE KEY MODIFICATION: VRF-shuffle the queue before greedy loop.
        self.apply_ooze_ordering(container);

        let mut budget = budget.saturating_sub(
            self.common
                .in_flight_tracker
                .cus_in_flight_per_thread()
                .iter()
                .sum(),
        );

        let starting_queue_size = container.queue_size();
        let starting_buffer_size = container.buffer_size();

        let num_threads = self.common.consume_work_senders.len();
        let target_cu_per_thread = self.config.target_scheduled_cus / num_threads as u64;

        let mut schedulable_threads = ThreadSet::any(num_threads);
        for thread_id in 0..num_threads {
            if self.common.in_flight_tracker.cus_in_flight_per_thread()[thread_id]
                >= target_cu_per_thread
            {
                schedulable_threads.remove(thread_id);
            }
        }
        if schedulable_threads.is_empty() {
            return Ok(SchedulingSummary {
                starting_queue_size,
                starting_buffer_size,
                ..SchedulingSummary::default()
            });
        }

        #[cfg(debug_assertions)]
        debug_assert!(
            self.common.batches.is_empty(),
            "batches must start empty for scheduling"
        );

        let mut num_scanned: usize = 0;
        let mut num_scheduled = Saturating::<usize>(0);
        let mut num_sent: usize = 0;
        let mut num_unschedulable_conflicts: usize = 0;
        let mut num_unschedulable_threads: usize = 0;

        while budget > 0
            && num_scanned < self.config.max_scanned_transactions_per_scheduling_pass
            && !schedulable_threads.is_empty()
            && !container.is_empty()
        {
            let Some(id) = container.pop() else {
                unreachable!("container is not empty")
            };

            num_scanned += 1;

            let Some(transaction_state) = container.get_mut_transaction_state(id.id) else {
                continue;
            };
            if !transaction_state.has_transaction() {
                continue;
            }

            match try_schedule_transaction(
                transaction_state,
                &mut self.common.account_locks,
                schedulable_threads,
                |thread_set| {
                    select_thread(
                        thread_set,
                        self.common.batches.total_cus(),
                        self.common.in_flight_tracker.cus_in_flight_per_thread(),
                        self.common.batches.transactions(),
                        self.common.in_flight_tracker.num_in_flight_per_thread(),
                    )
                },
            ) {
                Err(TransactionSchedulingError::UnschedulableConflicts) => {
                    num_unschedulable_conflicts += 1;
                    self.unschedulables.push(id);
                }
                Err(TransactionSchedulingError::UnschedulableThread) => {
                    num_unschedulable_threads += 1;
                    self.unschedulables.push(id);
                }
                Ok(TransactionSchedulingInfo {
                    thread_id,
                    transaction,
                    max_age,
                    cost,
                }) => {
                    num_scheduled += 1;
                    let transaction_bytes = transaction.serialized_size() as u64;
                    self.common.batches.add_transaction_to_batch(
                        thread_id,
                        id.id,
                        transaction,
                        max_age,
                        cost,
                        transaction_bytes,
                    );
                    budget = budget.saturating_sub(cost);

                    if self.common.batches.transactions()[thread_id].len()
                        >= self.config.target_transactions_per_batch
                    {
                        num_sent += self.common.send_batches()?;
                    }

                    if self.common.in_flight_tracker.cus_in_flight_per_thread()[thread_id]
                        + self.common.batches.total_cus()[thread_id]
                        >= target_cu_per_thread
                    {
                        schedulable_threads.remove(thread_id);
                        if schedulable_threads.is_empty() {
                            break;
                        }
                    }
                }
            }
        }

        num_sent += self.common.send_batches()?;
        let Saturating(num_scheduled) = num_scheduled;
        assert_eq!(
            num_scheduled, num_sent,
            "number of scheduled and sent transactions must match"
        );

        container.push_ids_into_queue(self.unschedulables.drain(..));

        Ok(SchedulingSummary {
            starting_queue_size,
            starting_buffer_size,
            num_scheduled,
            num_unschedulable_conflicts,
            num_unschedulable_threads,
        })
    }

    fn scheduling_common_mut(&mut self) -> &mut SchedulingCommon<Tx> {
        &mut self.common
    }
}

fn try_schedule_transaction<Tx: TransactionWithMeta>(
    transaction_state: &mut TransactionState<Tx>,
    account_locks: &mut ThreadAwareAccountLocks,
    schedulable_threads: ThreadSet,
    thread_selector: impl Fn(ThreadSet) -> ThreadId,
) -> Result<TransactionSchedulingInfo<Tx>, TransactionSchedulingError> {
    if !transaction_state.has_transaction() {
        // Tx was already taken (scheduled/in-flight) — not schedulable again.
        return Err(TransactionSchedulingError::UnschedulableConflicts);
    }
    let transaction = transaction_state.transaction();
    let account_keys = transaction.account_keys();
    let write_account_locks = account_keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| transaction.is_writable(index).then_some(key));
    let read_account_locks = account_keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| (!transaction.is_writable(index)).then_some(key));

    let thread_id = account_locks
        .try_lock_accounts(
            write_account_locks,
            read_account_locks,
            schedulable_threads,
            thread_selector,
        )
        .map_err(|err| match err {
            TryLockError::MultipleConflicts => TransactionSchedulingError::UnschedulableConflicts,
            TryLockError::ThreadNotAllowed => TransactionSchedulingError::UnschedulableThread,
        })?;

    let (transaction, max_age) = transaction_state.take_transaction_for_scheduling();
    let cost = transaction_state.cost();
    Ok(TransactionSchedulingInfo {
        thread_id,
        transaction,
        max_age,
        cost,
    })
}
