// ©AngelaMos | 2026
// reassembly.rs

//! Property tests for the TCP stream reassembler.
//!
//! The reassembler is the component an adversary reaches first: it consumes
//! attacker controlled sequence numbers and segment boundaries on every
//! connection. Two properties pin it down. The first is correctness under
//! reordering: any stream cut into any segments and delivered in any order
//! must reassemble back to the original bytes, because that is the whole job.
//! The second is the absence of panics under fully arbitrary input, because a
//! passive sensor that can be crashed by a crafted segment is a denial of
//! service waiting to happen.

use proptest::prelude::*;
use tlsfp_core::pipeline::flow::{PushOutcome, ReassemblyLimits, StreamReassembler};

fn generous_limits() -> ReassemblyLimits {
    ReassemblyLimits {
        max_assembled_bytes: 1 << 20,
        max_pending_bytes: 1 << 20,
        max_pending_segments: 4096,
    }
}

/// A stream plus its segment boundaries and a delivery permutation.
fn stream_and_delivery() -> impl Strategy<Value = (Vec<u8>, Vec<(usize, usize)>, Vec<usize>)> {
    prop::collection::vec(any::<u8>(), 1..2048).prop_flat_map(|data| {
        let len = data.len();
        let cuts = prop::collection::vec(0..len, 0..16);
        (Just(data), cuts).prop_flat_map(|(data, mut cuts)| {
            cuts.sort_unstable();
            cuts.dedup();
            let boundaries = boundaries_from_cuts(&cuts, data.len());
            let permutation = Just((0..boundaries.len()).collect::<Vec<_>>()).prop_shuffle();
            (Just(data), Just(boundaries), permutation)
        })
    })
}

fn boundaries_from_cuts(cuts: &[usize], len: usize) -> Vec<(usize, usize)> {
    let mut points = vec![0];
    points.extend(cuts.iter().copied().filter(|&c| c > 0 && c < len));
    points.push(len);
    points.dedup();
    points.windows(2).map(|w| (w[0], w[1])).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any segmentation delivered in any order reassembles to the original.
    #[test]
    fn arbitrary_segmentation_and_reordering_reconstructs_the_stream(
        (data, boundaries, permutation) in stream_and_delivery(),
    ) {
        let base_seq = 0x1234_5678u32;
        let mut reasm = StreamReassembler::new(generous_limits());
        reasm.anchor(base_seq);

        for &segment_index in &permutation {
            let (start, end) = boundaries[segment_index];
            let seq = base_seq.wrapping_add(u32::try_from(start).unwrap());
            reasm.push(seq, &data[start..end]);
        }

        prop_assert_eq!(reasm.data(), data.as_slice());
    }

    /// Duplicates layered on top of a complete stream change nothing.
    #[test]
    fn duplicate_delivery_is_idempotent(
        (data, boundaries, permutation) in stream_and_delivery(),
    ) {
        let base_seq = 42u32;
        let mut reasm = StreamReassembler::new(generous_limits());
        reasm.anchor(base_seq);

        for round in 0..2 {
            for &segment_index in &permutation {
                let (start, end) = boundaries[segment_index];
                let seq = base_seq.wrapping_add(u32::try_from(start).unwrap());
                let outcome = reasm.push(seq, &data[start..end]);
                if round == 1 {
                    prop_assert!(matches!(
                        outcome,
                        PushOutcome::Unchanged | PushOutcome::Grew
                    ));
                }
            }
        }
        prop_assert_eq!(reasm.data(), data.as_slice());
    }

    /// Fully arbitrary segments never panic and never exceed the cap.
    #[test]
    fn arbitrary_input_never_panics_or_overruns(
        segments in prop::collection::vec(
            (any::<u32>(), prop::collection::vec(any::<u8>(), 0..64)),
            0..256,
        ),
    ) {
        let limits = ReassemblyLimits {
            max_assembled_bytes: 512,
            max_pending_bytes: 512,
            max_pending_segments: 32,
        };
        let mut reasm = StreamReassembler::new(limits);
        for (seq, payload) in &segments {
            reasm.push(*seq, payload);
            prop_assert!(reasm.data().len() <= limits.max_assembled_bytes);
        }
    }
}
