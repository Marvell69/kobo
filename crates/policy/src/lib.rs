//! Per-customer velocity / spend-limit rules — new vs. octo.
//!
//! octo bounds risk at the gas-tank level (a fee budget). Kobo adds a second,
//! independent layer: a rolling-window cap on how much value a single
//! customer can move in a given period, so a compromised client credential
//! can drain at most the configured limit, not the whole wallet, before a
//! human has to approve more.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VelocityLimit {
    pub window_seconds: u64,
    pub max_amount_stroops: i128,
}

#[derive(Debug, Clone, Copy)]
struct Withdrawal {
    at_unix: u64,
    amount_stroops: i128,
}

#[derive(Debug, Default)]
pub struct CustomerLedger {
    recent: Vec<Withdrawal>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { attempted_total: i128, limit: i128 },
}

impl CustomerLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate whether `amount_stroops` at time `now_unix` would breach
    /// `limit`, without mutating state — callers record the withdrawal
    /// separately via [`record`] only after the transaction is actually
    /// relayed, so a rejected attempt never counts against the customer.
    pub fn evaluate(
        &self,
        limit: VelocityLimit,
        now_unix: u64,
        amount_stroops: i128,
    ) -> PolicyDecision {
        if limit.max_amount_stroops == 0 {
            return PolicyDecision::Allow; // 0 == unlimited, per .env.example
        }
        let window_start = now_unix.saturating_sub(limit.window_seconds);
        let already: i128 = self
            .recent
            .iter()
            .filter(|w| w.at_unix >= window_start)
            .map(|w| w.amount_stroops)
            .sum();
        let attempted_total = already + amount_stroops;
        if attempted_total > limit.max_amount_stroops {
            PolicyDecision::Deny {
                attempted_total,
                limit: limit.max_amount_stroops,
            }
        } else {
            PolicyDecision::Allow
        }
    }

    pub fn record(&mut self, now_unix: u64, amount_stroops: i128) {
        self.recent.push(Withdrawal {
            at_unix: now_unix,
            amount_stroops,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    #[test]
    fn allows_spend_under_the_cap() {
        let ledger = CustomerLedger::new();
        let limit = VelocityLimit { window_seconds: DAY, max_amount_stroops: 1_000_000_000 };
        assert_eq!(ledger.evaluate(limit, 1_000, 500_000_000), PolicyDecision::Allow);
    }

    #[test]
    fn denies_spend_that_would_breach_the_cap() {
        let mut ledger = CustomerLedger::new();
        let limit = VelocityLimit { window_seconds: DAY, max_amount_stroops: 1_000_000_000 };
        ledger.record(1_000, 800_000_000);
        let decision = ledger.evaluate(limit, 1_500, 300_000_000);
        assert_eq!(
            decision,
            PolicyDecision::Deny { attempted_total: 1_100_000_000, limit: 1_000_000_000 }
        );
    }

    #[test]
    fn withdrawals_outside_the_window_do_not_count() {
        let mut ledger = CustomerLedger::new();
        let limit = VelocityLimit { window_seconds: DAY, max_amount_stroops: 1_000_000_000 };
        ledger.record(1_000, 900_000_000);
        // 2 days later — the old withdrawal has rolled off the window.
        let decision = ledger.evaluate(limit, 1_000 + 2 * DAY, 900_000_000);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn zero_limit_means_unlimited() {
        let ledger = CustomerLedger::new();
        let limit = VelocityLimit { window_seconds: DAY, max_amount_stroops: 0 };
        assert_eq!(ledger.evaluate(limit, 1_000, i128::MAX / 2), PolicyDecision::Allow);
    }
}
