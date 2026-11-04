use std::collections::VecDeque;

use crate::AiError;

/// Daily call budget and per-minute cap; time is injected so it is testable.
#[derive(Debug)]
pub struct Limiter {
    daily: u32,
    per_minute: u32,
    day: u64,
    used_today: u32,
    recent: VecDeque<u64>,
}

impl Limiter {
    #[must_use]
    pub fn new(daily: u32, per_minute: u32) -> Self {
        Self {
            daily,
            per_minute,
            day: 0,
            used_today: 0,
            recent: VecDeque::new(),
        }
    }

    /// Reserve one call at `now` (unix seconds).
    ///
    /// # Errors
    /// [`AiError::Budget`] when either cap is exhausted.
    pub fn acquire(&mut self, now: u64) -> Result<(), AiError> {
        let day = now / 86_400;
        if day != self.day {
            self.day = day;
            self.used_today = 0;
        }
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= 60)
        {
            self.recent.pop_front();
        }
        if self.used_today >= self.daily || self.recent.len() >= self.per_minute as usize {
            return Err(AiError::Budget);
        }
        self.used_today += 1;
        self.recent.push_back(now);
        Ok(())
    }

    #[must_use]
    pub fn calls_today(&self) -> u32 {
        self.used_today
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_minute_cap_then_recovers_and_daily_budget_resets() {
        let mut l = Limiter::new(5, 2);
        assert!(l.acquire(1000).is_ok() && l.acquire(1001).is_ok());
        assert!(matches!(l.acquire(1002), Err(AiError::Budget)));
        assert!(l.acquire(1100).is_ok());
        let mut d = Limiter::new(2, 100);
        assert!(d.acquire(10).is_ok() && d.acquire(11).is_ok());
        assert!(matches!(d.acquire(12), Err(AiError::Budget)));
        assert!(d.acquire(86_400 + 5).is_ok());
    }
}
