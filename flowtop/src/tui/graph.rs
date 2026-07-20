use crate::aggregate::timeseries::AggregateBucket;

pub fn sparkline(buckets: &[AggregateBucket], width: usize, ascii: bool) -> String {
    let values = values_for_width(buckets, width);
    if values.is_empty() {
        return String::new();
    }
    let glyphs: Vec<char> = if ascii {
        "._-~=*#@".chars().collect()
    } else {
        "▁▂▃▄▅▆▇█".chars().collect()
    };
    let max = visible_max(&values);
    values
        .into_iter()
        .map(|value| {
            let normalized = normalize(value, max);
            let index = (normalized * (glyphs.len() - 1) as f64).round() as usize;
            glyphs[index]
        })
        .collect()
}

/// Renders a filled chart that uses every available row and column.
pub fn chart_lines(
    buckets: &[AggregateBucket],
    width: usize,
    height: usize,
    ascii: bool,
) -> Vec<String> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let values = values_for_width(buckets, width);
    if values.is_empty() {
        return vec![" ".repeat(width); height];
    }
    let max = visible_max(&values);
    let unicode_blocks = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    (0..height)
        .map(|row| {
            let cell_floor = (height - row - 1) * 8;
            values
                .iter()
                .map(|value| {
                    let normalized = normalize(*value, max);
                    let mut filled = (normalized * (height * 8) as f64).round() as usize;
                    // Keep a visible baseline for a sampled zero value.
                    if filled == 0 && row + 1 == height {
                        filled = 1;
                    }
                    let in_cell = filled.saturating_sub(cell_floor).min(8);
                    if ascii {
                        match in_cell {
                            0 => ' ',
                            1 if row + 1 == height => '.',
                            _ => '#',
                        }
                    } else {
                        unicode_blocks[in_cell]
                    }
                })
                .collect()
        })
        .collect()
}

fn values_for_width(buckets: &[AggregateBucket], width: usize) -> Vec<f64> {
    if width == 0 || buckets.is_empty() {
        return Vec::new();
    }
    let timeline_start = buckets[0].start_ns;
    let timeline_end = buckets
        .last()
        .map(|bucket| bucket.end_ns.max(bucket.start_ns))
        .unwrap_or(timeline_start);
    let duration = timeline_end.saturating_sub(timeline_start);
    if duration == 0 {
        let max = buckets
            .iter()
            .map(|bucket| bucket.max)
            .filter(|value| value.is_finite())
            .fold(0.0_f64, f64::max);
        return vec![max; width];
    }

    let column_for = |timestamp_ns: u64| {
        let offset = timestamp_ns.saturating_sub(timeline_start) as u128;
        let last_column = width.saturating_sub(1) as u128;
        ((offset * last_column) / duration as u128).min(last_column) as usize
    };
    let mut values = vec![0.0_f64; width];
    for (index, bucket) in buckets.iter().enumerate() {
        if !bucket.max.is_finite() {
            continue;
        }
        let start_column = column_for(bucket.start_ns);
        let end_column = buckets
            .get(index + 1)
            .map(|next| {
                column_for(next.start_ns)
                    .saturating_sub(1)
                    .max(start_column)
            })
            .unwrap_or(width - 1);
        for value in &mut values[start_column..=end_column] {
            *value = value.max(bucket.max);
        }
    }
    values
}

fn visible_max(values: &[f64]) -> f64 {
    values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .fold(0.0_f64, f64::max)
}

fn normalize(value: f64, max: f64) -> f64 {
    if max <= 0.0 || !value.is_finite() {
        0.0
    } else {
        (value / max).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_preserves_peak_and_fills_width() {
        let buckets = [
            AggregateBucket::sample(0, 0.0),
            AggregateBucket::sample(1, 10.0),
        ];
        assert_eq!(sparkline(&buckets, 2, false), "▁█");
        assert_eq!(sparkline(&buckets, 5, true).chars().count(), 5);
        assert!(sparkline(&buckets, 5, true).ends_with('@'));
    }

    #[test]
    fn vertical_chart_uses_requested_dimensions() {
        let buckets = [
            AggregateBucket::sample(0, 0.0),
            AggregateBucket::sample(1, 10.0),
        ];
        let lines = chart_lines(&buckets, 8, 3, false);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.chars().count() == 8));
        assert!(lines[0].ends_with('█'));
        assert!(lines[2].starts_with('▁'));
    }

    #[test]
    fn historical_peak_only_moves_left_as_timeline_grows() {
        let histories = [
            vec![
                AggregateBucket::sample(0, 0.0),
                AggregateBucket::sample(10, 10.0),
                AggregateBucket::sample(20, 0.0),
            ],
            vec![
                AggregateBucket::sample(0, 0.0),
                AggregateBucket::sample(10, 10.0),
                AggregateBucket::sample(20, 0.0),
                AggregateBucket::sample(30, 0.0),
            ],
            vec![
                AggregateBucket::sample(0, 0.0),
                AggregateBucket::sample(10, 10.0),
                AggregateBucket::sample(20, 0.0),
                AggregateBucket::sample(30, 0.0),
                AggregateBucket::sample(40, 0.0),
            ],
        ];
        let peak_columns: Vec<usize> = histories
            .iter()
            .map(|buckets| {
                values_for_width(buckets, 21)
                    .iter()
                    .position(|value| *value == 10.0)
                    .unwrap()
            })
            .collect();

        assert!(peak_columns.windows(2).all(|pair| pair[1] <= pair[0]));
    }

    #[test]
    fn uneven_bucket_counts_use_timestamp_positions() {
        let buckets = [
            AggregateBucket::sample(0, 1.0),
            AggregateBucket::sample(10, 2.0),
            AggregateBucket::sample(90, 3.0),
            AggregateBucket::sample(100, 4.0),
        ];
        let values = values_for_width(&buckets, 11);

        assert_eq!(&values[..1], &[1.0]);
        assert_eq!(&values[1..9], &[2.0; 8]);
        assert_eq!(values[9], 3.0);
        assert_eq!(values[10], 4.0);
    }
}
