//! Summary statistics over repeated runs and latency samples.

use crate::json::Json;

/// The median, minimum and maximum of a set of repeated measurements.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Spread {
    /// The median; for an even count, the mean of the two middle values.
    pub median: f64,
    /// The smallest value.
    pub min: f64,
    /// The largest value.
    pub max: f64,
}

impl Spread {
    /// Summarises `values`, or returns `None` when there are none (or one is NaN).
    pub fn of(values: &[f64]) -> Option<Spread> {
        if values.is_empty() || values.iter().any(|v| v.is_nan()) {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        let mid = sorted.len() / 2;
        let median = if sorted.len() % 2 == 1 {
            sorted[mid]
        } else {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        };
        Some(Spread { median, min: sorted[0], max: sorted[sorted.len() - 1] })
    }

    /// Returns `{"median": .., "min": .., "max": ..}`.
    pub fn to_json(self) -> Json {
        Json::object().with("median", self.median).with("min", self.min).with("max", self.max)
    }
}

/// Returns the `p`-th percentile (0 to 100) of `sorted` by the nearest-rank method, the
/// smallest value with at least `p` percent of the values at or below it.
///
/// Returns 0 for an empty slice.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // The epsilon absorbs the rounding of decimal percentages such as 99.9, which would
    // otherwise move an exact rank up by one.
    let rank = (p * sorted.len() as f64 / 100.0 - 1e-9).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_of_odd_and_even_counts() {
        assert_eq!(Spread::of(&[3.0, 1.0, 2.0]), Some(Spread { median: 2.0, min: 1.0, max: 3.0 }));
        assert_eq!(Spread::of(&[4.0, 1.0, 2.0, 3.0]).map(|s| s.median), Some(2.5));
        assert_eq!(Spread::of(&[]), None);
        assert_eq!(Spread::of(&[f64::NAN]), None);
    }

    #[test]
    fn nearest_rank_percentiles() {
        let values: Vec<u64> = (1..=1000).collect();
        assert_eq!(percentile(&values, 50.0), 500);
        assert_eq!(percentile(&values, 99.0), 990);
        assert_eq!(percentile(&values, 99.9), 999);
        assert_eq!(percentile(&values, 100.0), 1000);
        assert_eq!(percentile(&values, 0.0), 1);
        assert_eq!(percentile(&[], 50.0), 0);
        assert_eq!(percentile(&[7], 99.9), 7);
    }
}
