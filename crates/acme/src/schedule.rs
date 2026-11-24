//! When to renew a certificate, and how long to wait after a failure (SID 0021).
//!
//! Both functions are modelled in `docs/sid/assets/automatic-https.lean`, which proves
//! that a renewal is due inside the life of the certificate and that the delay is
//! bounded and monotone.

/// The delay after the first failure, in seconds.
pub const FIRST_DELAY: u64 = 120;
/// The longest delay between two attempts, in seconds: one day.
pub const LONGEST_DELAY: u64 = 86_400;
/// The delay stops doubling after this many doublings.
const MAX_DOUBLINGS: u32 = 10;

/// The time to renew a certificate that is valid from `not_before` to `not_after`: when
/// one third of its life remains. For `not_before < not_after` the result is at least
/// `not_before` and less than `not_after`. A certificate without a life is due at once.
pub fn renew_at(not_before: u64, not_after: u64) -> u64 {
    let life = not_after.saturating_sub(not_before);
    // `life / 3 * 2` cannot overflow, and the remainder adds at most one second.
    not_before + life / 3 * 2 + life % 3 * 2 / 3
}

/// The seconds to wait after `failures` consecutive failures, counted from one: two
/// minutes, doubled for each further failure, at most one day. `retry_after` is the wait
/// that the authority asked for. It can lengthen the delay, up to one day.
pub fn retry_delay(failures: u32, retry_after: Option<u64>) -> u64 {
    let doublings = failures.saturating_sub(1).min(MAX_DOUBLINGS);
    let delay = (FIRST_DELAY << doublings).min(LONGEST_DELAY);
    delay.max(retry_after.unwrap_or(0).min(LONGEST_DELAY))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_is_inside_the_life_of_the_certificate() {
        assert_eq!(renew_at(0, 90 * 86_400), 60 * 86_400);
        assert_eq!(renew_at(1000, 1001), 1000);
        assert_eq!(renew_at(1000, 1002), 1001);
        assert_eq!(renew_at(1000, 1003), 1002);
        for life in 1..500 {
            for start in [0, 7, u64::MAX - 500] {
                let due = renew_at(start, start + life);
                assert!(start <= due && due < start + life, "{start} {life}");
                // The same value as the formula of the record.
                assert_eq!(u128::from(due), u128::from(start) + 2 * u128::from(life) / 3);
            }
        }
        assert_eq!(renew_at(u64::MAX - 3, u64::MAX), u64::MAX - 1);
    }

    #[test]
    fn a_certificate_without_a_life_is_due_at_once() {
        assert_eq!(renew_at(500, 500), 500);
        assert_eq!(renew_at(500, 100), 500);
    }

    #[test]
    fn the_delay_doubles_to_one_day() {
        let delays: Vec<u64> = (1..=12).map(|n| retry_delay(n, None)).collect();
        let expected =
            [120, 240, 480, 960, 1920, 3840, 7680, 15_360, 30_720, 61_440, 86_400, 86_400];
        assert_eq!(delays, expected);
        assert_eq!(retry_delay(0, None), 120);
        assert_eq!(retry_delay(u32::MAX, None), LONGEST_DELAY);
    }

    #[test]
    fn the_delay_is_monotone_and_bounded() {
        for failures in 0..40 {
            let delay = retry_delay(failures, None);
            assert!((FIRST_DELAY..=LONGEST_DELAY).contains(&delay));
            assert!(delay <= retry_delay(failures + 1, None));
        }
    }

    #[test]
    fn the_authority_can_lengthen_the_delay_up_to_one_day() {
        assert_eq!(retry_delay(1, Some(30)), 120);
        assert_eq!(retry_delay(1, Some(3600)), 3600);
        assert_eq!(retry_delay(1, Some(u64::MAX)), LONGEST_DELAY);
    }

    #[test]
    fn the_first_hour_holds_at_most_five_attempts() {
        // Attempts at 0, then after each delay. Let's Encrypt allows five failed
        // validations per name and hour.
        let mut at = 0;
        let mut attempts = 1;
        for failures in 1.. {
            at += retry_delay(failures, None);
            if at >= 3600 {
                break;
            }
            attempts += 1;
        }
        assert_eq!(attempts, 5);
    }
}
