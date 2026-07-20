use std::collections::{HashMap, VecDeque};

use crate::aggregate::snapshot::MetricSnapshot;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AggregateBucket {
    pub start_ns: u64,
    pub end_ns: u64,
    pub count: u64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub last: f64,
}

impl AggregateBucket {
    pub fn sample(timestamp_ns: u64, value: f64) -> Self {
        Self {
            start_ns: timestamp_ns,
            end_ns: timestamp_ns,
            count: 1,
            min: value,
            max: value,
            avg: value,
            last: value,
        }
    }

    pub fn merge(self, other: Self) -> Self {
        let count = self.count.saturating_add(other.count);
        let avg = if count == 0 {
            0.0
        } else {
            (self.avg * self.count as f64 + other.avg * other.count as f64) / count as f64
        };
        Self {
            start_ns: self.start_ns.min(other.start_ns),
            end_ns: self.end_ns.max(other.end_ns),
            count,
            min: self.min.min(other.min),
            max: self.max.max(other.max),
            avg,
            last: other.last,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultiResolutionSeries {
    levels: Vec<VecDeque<AggregateBucket>>,
    pending: Vec<Option<AggregateBucket>>,
    capacity_per_level: usize,
    samples: u64,
}

impl MultiResolutionSeries {
    pub fn new(capacity_per_level: usize) -> Self {
        assert!(capacity_per_level >= 2);
        Self {
            levels: vec![VecDeque::new()],
            pending: vec![None],
            capacity_per_level,
            samples: 0,
        }
    }

    pub fn push(&mut self, timestamp_ns: u64, value: f64) {
        self.samples = self.samples.saturating_add(1);
        self.push_bucket(0, AggregateBucket::sample(timestamp_ns, value));
    }

    fn push_bucket(&mut self, level: usize, bucket: AggregateBucket) {
        self.ensure_level(level);
        self.levels[level].push_back(bucket);
        if self.levels[level].len() > self.capacity_per_level {
            self.levels[level].pop_front();
        }

        if let Some(first) = self.pending[level].take() {
            let merged = first.merge(bucket);
            self.push_bucket(level + 1, merged);
        } else {
            self.pending[level] = Some(bucket);
        }
    }

    fn ensure_level(&mut self, level: usize) {
        while self.levels.len() <= level {
            self.levels.push(VecDeque::new());
            self.pending.push(None);
        }
    }

    pub fn buckets_for_width(&self, width: usize) -> Vec<AggregateBucket> {
        if width == 0 || self.samples == 0 {
            return Vec::new();
        }
        let target = width.min(self.capacity_per_level).max(1);
        let mut selected_level = 0;
        for level in 0..self.levels.len() {
            let bucket_span = 1_u64.checked_shl(level as u32).unwrap_or(u64::MAX);
            let required = self.samples.div_ceil(bucket_span);
            if required <= target as u64 && self.levels[level].len() as u64 >= required / 2 {
                selected_level = level;
                break;
            }
            selected_level = level;
        }

        let mut result: Vec<AggregateBucket> =
            self.levels[selected_level].iter().copied().collect();
        if let Some(mut cursor) = result.last().map(|bucket| bucket.end_ns) {
            for level in (0..selected_level).rev() {
                for bucket in &self.levels[level] {
                    if bucket.start_ns > cursor {
                        result.push(*bucket);
                        cursor = bucket.end_ns;
                    }
                }
            }
        }
        result.sort_by_key(|bucket| bucket.start_ns);
        result
            .dedup_by(|left, right| left.start_ns == right.start_ns && left.end_ns == right.end_ns);
        compress_to_width(result, target)
    }

    pub fn max_value(&self) -> Option<f64> {
        self.levels
            .iter()
            .flat_map(|level| level.iter().map(|bucket| bucket.max))
            .filter(|value| value.is_finite())
            .reduce(f64::max)
    }

    pub fn reset(&mut self) {
        self.levels.clear();
        self.levels.push(VecDeque::new());
        self.pending.clear();
        self.pending.push(None);
        self.samples = 0;
    }

    #[cfg(test)]
    pub fn stored_bucket_count(&self) -> usize {
        self.levels.iter().map(VecDeque::len).sum()
    }
}

fn compress_to_width(mut buckets: Vec<AggregateBucket>, width: usize) -> Vec<AggregateBucket> {
    if buckets.len() <= width {
        return buckets;
    }
    let mut compressed = Vec::with_capacity(width);
    for column in 0..width {
        let start = column * buckets.len() / width;
        let end = (column + 1) * buckets.len() / width;
        let mut merged = buckets[start];
        for bucket in &buckets[start + 1..end] {
            merged = merged.merge(*bucket);
        }
        compressed.push(merged);
    }
    buckets.clear();
    compressed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    Accepted,
    Connected,
    Unknown,
    TimeWait,
    CloseWait,
    AcceptRate,
    ConnectRate,
    CloseRate,
    Rx,
    Tx,
    Cpu,
    Memory,
    DiskRead,
    DiskWrite,
}

#[derive(Clone)]
pub struct TimeSeriesStore {
    series: HashMap<Metric, MultiResolutionSeries>,
    capacity_per_level: usize,
}

impl TimeSeriesStore {
    pub fn new(capacity_per_level: usize) -> Self {
        Self {
            series: HashMap::new(),
            capacity_per_level,
        }
    }

    pub fn push_snapshot(&mut self, snapshot: &MetricSnapshot) {
        let timestamp = snapshot.monotonic_ns;
        let values = [
            (
                Metric::Accepted,
                snapshot.tcp.accepted_established.map(|v| v as f64),
            ),
            (
                Metric::Connected,
                snapshot.tcp.connected_established.map(|v| v as f64),
            ),
            (
                Metric::Unknown,
                Some(snapshot.tcp.unknown_established as f64),
            ),
            (Metric::TimeWait, Some(snapshot.tcp.time_wait as f64)),
            (Metric::CloseWait, Some(snapshot.tcp.close_wait as f64)),
            (Metric::AcceptRate, snapshot.tcp.accepted_per_sec),
            (Metric::ConnectRate, snapshot.tcp.connected_per_sec),
            (Metric::CloseRate, snapshot.tcp.closed_per_sec),
            (Metric::Rx, Some(snapshot.network.host_rx_bytes_per_sec)),
            (Metric::Tx, Some(snapshot.network.host_tx_bytes_per_sec)),
            (Metric::Cpu, Some(snapshot.system.cpu_total_percent)),
            (Metric::Memory, Some(snapshot.system.memory_used_percent)),
            (
                Metric::DiskRead,
                Some(snapshot.system.disk_read_bytes_per_sec),
            ),
            (
                Metric::DiskWrite,
                Some(snapshot.system.disk_write_bytes_per_sec),
            ),
        ];
        for (metric, value) in values {
            if let Some(value) = value {
                self.series
                    .entry(metric)
                    .or_insert_with(|| MultiResolutionSeries::new(self.capacity_per_level))
                    .push(timestamp, value);
            }
        }
    }

    pub fn buckets(&self, metric: Metric, width: usize) -> Vec<AggregateBucket> {
        self.series
            .get(&metric)
            .map(|series| series.buckets_for_width(width))
            .unwrap_or_default()
    }

    pub fn max_value(&self, metric: Metric) -> Option<f64> {
        self.series
            .get(&metric)
            .and_then(MultiResolutionSeries::max_value)
    }

    pub fn time_bounds(&self) -> Option<(u64, u64)> {
        self.series
            .values()
            .filter_map(|series| {
                let buckets = series.buckets_for_width(2);
                Some((buckets.first()?.start_ns, buckets.last()?.end_ns))
            })
            .reduce(|left, right| (left.0.min(right.0), left.1.max(right.1)))
    }

    pub fn reset(&mut self) {
        self.series
            .values_mut()
            .for_each(MultiResolutionSeries::reset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_merge_is_weighted_and_keeps_peak() {
        let a = AggregateBucket::sample(1, 2.0);
        let b = AggregateBucket::sample(2, 10.0);
        let merged = a.merge(b);
        assert_eq!(merged.count, 2);
        assert_eq!(merged.avg, 6.0);
        assert_eq!(merged.max, 10.0);
        assert_eq!(merged.last, 10.0);
    }

    #[test]
    fn series_is_bounded_and_covers_full_range() {
        let mut series = MultiResolutionSeries::new(64);
        for value in 0..10_000 {
            series.push(value, value as f64);
        }
        let buckets = series.buckets_for_width(40);
        assert!(buckets.len() <= 40);
        assert_eq!(buckets.first().unwrap().start_ns, 0);
        assert_eq!(buckets.last().unwrap().end_ns, 9_999);
        assert_eq!(buckets.last().unwrap().max, 9_999.0);
        assert!(series.stored_bucket_count() < 64 * 20);
    }

    #[test]
    fn reset_drops_history() {
        let mut series = MultiResolutionSeries::new(8);
        series.push(1, 1.0);
        series.reset();
        assert!(series.buckets_for_width(10).is_empty());
        assert_eq!(series.max_value(), None);
    }

    #[test]
    fn store_reports_peak_value() {
        let mut store = TimeSeriesStore::new(8);
        let series = store
            .series
            .entry(Metric::Cpu)
            .or_insert_with(|| MultiResolutionSeries::new(8));
        series.push(10, 1.5);
        series.push(20, 9.5);
        series.push(30, 4.0);

        assert_eq!(store.max_value(Metric::Cpu), Some(9.5));
    }

    #[test]
    fn store_reports_full_time_bounds() {
        let mut store = TimeSeriesStore::new(8);
        let series = store
            .series
            .entry(Metric::Cpu)
            .or_insert_with(|| MultiResolutionSeries::new(8));
        series.push(10, 1.0);
        series.push(20, 2.0);
        assert_eq!(store.time_bounds(), Some((10, 20)));
    }
}
