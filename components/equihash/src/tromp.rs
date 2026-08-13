//! Rust interface to the tromp equihash solver.

use std::marker::{PhantomData, PhantomPinned};
use std::slice;
use std::vec::Vec;

use blake2b_simd::State;

use crate::{blake2b, minimal::minimal_from_indices, params::Params, verify};

/// A point where the Tromp solver can stop without interrupting an FFI call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPoint {
    /// The solver has not started the next nonce.
    NonceBoundary,
    /// The solver has finished one digit round.
    DigitBoundary,
}

/// The outcome of a cancellable solve operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellableSolveOutcome<T> {
    /// The solver found solutions or exhausted the nonce source.
    Completed(T),
    /// The cancellation callback stopped the solver.
    Cancelled,
}

/// The outcome and pass counts from a cancellable solve operation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "the solve result reports whether cancellation discarded work"]
pub struct CancellableSolveResult<T> {
    outcome: CancellableSolveOutcome<T>,
    passes_completed: u64,
    passes_abandoned: u64,
}

impl<T> CancellableSolveResult<T> {
    fn new(
        outcome: CancellableSolveOutcome<T>,
        passes_completed: u64,
        passes_abandoned: u64,
    ) -> Self {
        Self {
            outcome,
            passes_completed,
            passes_abandoned,
        }
    }

    fn map<U>(self, map_value: impl FnOnce(T) -> U) -> CancellableSolveResult<U> {
        let outcome = match self.outcome {
            CancellableSolveOutcome::Completed(value) => {
                CancellableSolveOutcome::Completed(map_value(value))
            }
            CancellableSolveOutcome::Cancelled => CancellableSolveOutcome::Cancelled,
        };

        CancellableSolveResult::new(outcome, self.passes_completed, self.passes_abandoned)
    }

    /// Returns the solve outcome.
    pub fn outcome(&self) -> &CancellableSolveOutcome<T> {
        &self.outcome
    }

    /// Consumes the result and returns the solve outcome.
    pub fn into_outcome(self) -> CancellableSolveOutcome<T> {
        self.outcome
    }

    /// Returns the number of full passes whose output the solver retained.
    pub fn passes_completed(&self) -> u64 {
        self.passes_completed
    }

    /// Returns the number of passes whose output cancellation discarded.
    pub fn passes_abandoned(&self) -> u64 {
        self.passes_abandoned
    }
}

#[repr(C)]
struct CEqui {
    _f: [u8; 0],
    _m: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "equitromp")]
unsafe extern "C" {
    #[allow(improper_ctypes)]
    fn equi_new(
        blake2b_clone: extern "C" fn(state: *const State) -> *mut State,
        blake2b_free: extern "C" fn(state: *mut State),
        blake2b_update: extern "C" fn(state: *mut State, input: *const u8, input_len: usize),
        blake2b_finalize: extern "C" fn(state: *mut State, output: *mut u8, output_len: usize),
    ) -> *mut CEqui;
    fn equi_free(eq: *mut CEqui);
    #[allow(improper_ctypes)]
    fn equi_setstate(eq: *mut CEqui, ctx: *const State);
    fn equi_clearslots(eq: *mut CEqui);
    fn equi_digit0(eq: *mut CEqui, id: u32);
    fn equi_digitodd(eq: *mut CEqui, r: u32, id: u32);
    fn equi_digiteven(eq: *mut CEqui, r: u32, id: u32);
    fn equi_digitK(eq: *mut CEqui, id: u32);
    fn equi_nsols(eq: *const CEqui) -> usize;
    /// Returns `equi_nsols()` solutions of length `2^K`, in a single memory allocation.
    fn equi_sols(eq: *const CEqui) -> *const u32;
}

enum WorkerOutcome {
    Completed(Vec<Vec<u32>>),
    Cancelled,
}

/// Performs a single equihash solver run with equihash parameters `p` and hash state `curr_state`.
/// Returns zero or more unique solutions.
///
/// # SAFETY
///
/// The parameters to this function must match the hard-coded parameters in the C++ code.
///
/// This function uses unsafe code for FFI into the tromp solver.
#[allow(unsafe_code)]
#[allow(clippy::print_stdout)]
unsafe fn worker(
    eq: *mut CEqui,
    p: Params,
    curr_state: &State,
    should_cancel: &mut impl FnMut(CancellationPoint) -> bool,
) -> WorkerOutcome {
    // SAFETY: caller must supply a valid `eq` instance.
    //
    // Review Note: nsols is set to zero in C++ here
    unsafe { equi_setstate(eq, curr_state) };

    // Initialization done, start algo driver.
    unsafe { equi_digit0(eq, 0) };
    unsafe { equi_clearslots(eq) };
    // SAFETY: caller must supply a `p` instance that matches the hard-coded values in the C code.
    for r in 1..p.k {
        if should_cancel(CancellationPoint::DigitBoundary) {
            return WorkerOutcome::Cancelled;
        }

        if (r & 1) != 0 {
            unsafe { equi_digitodd(eq, r, 0) }
        } else {
            unsafe { equi_digiteven(eq, r, 0) }
        };
        unsafe { equi_clearslots(eq) };
    }

    if should_cancel(CancellationPoint::DigitBoundary) {
        return WorkerOutcome::Cancelled;
    }

    // Review Note: nsols is increased here, but only if the solution passes the strictly ordered check.
    // With 256 nonces, we get to around 6/9 digits strictly ordered.
    unsafe { equi_digitK(eq, 0) };

    if should_cancel(CancellationPoint::DigitBoundary) {
        return WorkerOutcome::Cancelled;
    }

    {
        let nsols = unsafe { equi_nsols(eq) };
        let sols = unsafe { equi_sols(eq) };
        let solution_len = 1 << p.k;
        //println!("{nsols} solutions of length {solution_len} at {sols:?}");

        // SAFETY:
        // - caller must supply a `p` instance that matches the hard-coded values in the C code.
        // - `sols` is a single allocation containing at least `nsols` solutions.
        // - this slice is a shared ref to the memory in a valid `eq` instance supplied by the caller.
        let solutions: &[u32] = unsafe { slice::from_raw_parts(sols, nsols * solution_len) };

        /*
        println!(
            "{nsols} solutions of length {solution_len} as a slice of length {:?}",
            solutions.len()
        );
        */

        let mut chunks = solutions.chunks_exact(solution_len);

        // SAFETY:
        // - caller must supply a `p` instance that matches the hard-coded values in the C code.
        // - each solution contains `solution_len` u32 values.
        // - the temporary slices are shared refs to a valid `eq` instance supplied by the caller.
        // - the bytes in the shared ref are copied before they are returned.
        // - dropping `solutions: &[u32]` does not drop the underlying memory owned by `eq`.
        let mut solutions = (&mut chunks)
            .map(|solution| solution.to_vec())
            .collect::<Vec<_>>();

        assert_eq!(chunks.remainder().len(), 0);

        // Sometimes the solver returns identical solutions.
        solutions.sort();
        solutions.dedup();

        /*
        println!(
            "{} solutions as cloned vectors of length {:?}",
            solutions.len(),
            solutions
                .iter()
                .map(|solution| solution.len())
                .collect::<Vec<_>>()
        );
        */

        WorkerOutcome::Completed(solutions)
    }
}

/// Performs multiple equihash solver runs with equihash parameters `200, 9`, initialising the hash with
/// the supplied partial `input`. Between each run, generates a new nonce of length `N` using the
/// `next_nonce` function.
///
/// Returns zero or more unique solutions.
fn solve_200_9_uncompressed_cancellable<const N: usize>(
    input: &[u8],
    mut next_nonce: impl FnMut() -> Option<[u8; N]>,
    mut should_cancel: impl FnMut(CancellationPoint) -> bool,
) -> CancellableSolveResult<Vec<Vec<u32>>> {
    let p = Params::new(200, 9).expect("should be valid");
    let mut state = verify::initialise_state(p.n, p.k, p.hash_output());
    state.update(input);

    // Create solver and initialize it.
    //
    // # SAFETY
    // - the parameters 200,9 match the hard-coded parameters in the C++ code.
    // - tromp is compiled without multi-threading support, so each instance can only support 1 thread.
    // - the blake2b functions are in the correct order in Rust and C++ initializers.
    #[allow(unsafe_code)]
    let eq = unsafe {
        equi_new(
            blake2b::blake2b_clone,
            blake2b::blake2b_free,
            blake2b::blake2b_update,
            blake2b::blake2b_finalize,
        )
    };

    let mut passes_completed: u64 = 0;
    let mut passes_abandoned: u64 = 0;

    let outcome = loop {
        if should_cancel(CancellationPoint::NonceBoundary) {
            break CancellableSolveOutcome::Cancelled;
        }

        let nonce = match next_nonce() {
            Some(nonce) => nonce,
            None => break CancellableSolveOutcome::Completed(vec![]),
        };

        let mut curr_state = state.clone();
        // Review Note: these hashes are changing when the nonce changes
        curr_state.update(&nonce);

        // SAFETY:
        // - the parameters 200,9 match the hard-coded parameters in the C++ code.
        // - the eq instance is initilized above.
        #[allow(unsafe_code)]
        let worker_outcome = unsafe { worker(eq, p, &curr_state, &mut should_cancel) };
        match worker_outcome {
            WorkerOutcome::Completed(solutions) => {
                passes_completed = passes_completed.saturating_add(1);
                if !solutions.is_empty() {
                    break CancellableSolveOutcome::Completed(solutions);
                }
            }
            WorkerOutcome::Cancelled => {
                passes_abandoned = passes_abandoned.saturating_add(1);
                break CancellableSolveOutcome::Cancelled;
            }
        }
    };

    // SAFETY:
    // - the eq instance is initilized above, and not used after this point.
    #[allow(unsafe_code)]
    unsafe {
        equi_free(eq)
    };

    CancellableSolveResult::new(outcome, passes_completed, passes_abandoned)
}

/// Performs multiple Equihash solver passes with parameters `200, 9`.
///
/// The solver calls `should_cancel` before each nonce, between digit rounds,
/// and after the final digit round. Returning `true` before a nonce preserves
/// the previous pass. Returning `true` at a digit boundary discards the current
/// pass and any solution that it found.
pub fn solve_200_9_cancellable<const N: usize>(
    input: &[u8],
    next_nonce: impl FnMut() -> Option<[u8; N]>,
    should_cancel: impl FnMut(CancellationPoint) -> bool,
) -> CancellableSolveResult<Vec<Vec<u8>>> {
    let p = Params::new(200, 9).expect("should be valid");

    solve_200_9_uncompressed_cancellable(input, next_nonce, should_cancel).map(|solutions| {
        let mut solutions = solutions
            .iter()
            .map(|solution| minimal_from_indices(p, solution))
            .collect::<Vec<_>>();

        solutions.sort();
        solutions.dedup();
        solutions
    })
}

/// Performs multiple equihash solver runs with equihash parameters `200, 9`, initialising the hash with
/// the supplied partial `input`. Between each run, generates a new nonce of length `N` using the
/// `next_nonce` function.
///
/// Returns zero or more unique compressed solutions.
pub fn solve_200_9<const N: usize>(
    input: &[u8],
    next_nonce: impl FnMut() -> Option<[u8; N]>,
) -> Vec<Vec<u8>> {
    match solve_200_9_cancellable(input, next_nonce, |_| false).into_outcome() {
        CancellableSolveOutcome::Completed(solutions) => solutions,
        CancellableSolveOutcome::Cancelled => {
            unreachable!("the cancellation callback always returns false")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::println;

    use super::{
        CancellableSolveOutcome, CancellationPoint, WorkerOutcome, equi_free, equi_new,
        solve_200_9, solve_200_9_cancellable, worker,
    };
    use crate::{blake2b, params::Params, verify};

    #[test]
    #[allow(clippy::print_stdout)]
    fn run_solver() {
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        let mut nonce: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut nonces = 0..=32_u32;
        let nonce_count = nonces.clone().count();

        let solutions = solve_200_9(input, || {
            let variable_nonce = nonces.next()?;
            println!("Using variable nonce [0..4] of {}", variable_nonce);

            let variable_nonce = variable_nonce.to_le_bytes();
            nonce[0] = variable_nonce[0];
            nonce[1] = variable_nonce[1];
            nonce[2] = variable_nonce[2];
            nonce[3] = variable_nonce[3];

            Some(nonce)
        });

        if solutions.is_empty() {
            // Expected solution rate is documented at:
            // https://github.com/tromp/equihash/blob/master/README.md
            panic!("Found no solutions after {nonce_count} runs, expected 1.88 solutions per run",);
        } else {
            println!("Found {} solutions:", solutions.len());
            for (sol_num, solution) in solutions.iter().enumerate() {
                println!("Validating solution {sol_num}:-\n{}", hex::encode(solution));
                crate::is_valid_solution(200, 9, input, &nonce, solution).unwrap_or_else(|error| {
                    panic!(
                        "unexpected invalid equihash 200, 9 solution:\n\
                             error: {error:?}\n\
                             input: {input:?}\n\
                             nonce: {nonce:?}\n\
                             solution: {solution:?}"
                    )
                });
                println!("Solution {sol_num} is valid!\n");
            }
        }
    }

    #[test]
    fn nonce_exhaustion_is_not_cancellation() {
        let result = solve_200_9_cancellable::<32>(b"input", || None, |_| false);

        assert_eq!(
            result.outcome(),
            &CancellableSolveOutcome::Completed(vec![])
        );
        assert_eq!(result.passes_completed(), 0);
        assert_eq!(result.passes_abandoned(), 0);
    }

    #[test]
    fn cancellation_before_a_nonce_does_not_abandon_a_pass() {
        let result = solve_200_9_cancellable::<32>(
            b"input",
            || Some([0; 32]),
            |point| point == CancellationPoint::NonceBoundary,
        );

        assert_eq!(result.outcome(), &CancellableSolveOutcome::Cancelled);
        assert_eq!(result.passes_completed(), 0);
        assert_eq!(result.passes_abandoned(), 0);
    }

    #[test]
    fn nonce_boundary_cancellation_preserves_a_completed_solution() {
        let mut nonce = [0; 32];
        nonce[0] = 1;
        let mut stop_requested = false;

        let result = solve_200_9_cancellable(
            b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
            || Some(nonce),
            |point| match point {
                CancellationPoint::NonceBoundary => stop_requested,
                CancellationPoint::DigitBoundary => {
                    stop_requested = true;
                    false
                }
            },
        );

        let CancellableSolveOutcome::Completed(solutions) = result.outcome() else {
            panic!("nonce-boundary cancellation discarded a completed pass")
        };
        assert!(!solutions.is_empty());
        assert_eq!(result.passes_completed(), 1);
        assert_eq!(result.passes_abandoned(), 0);
    }

    #[test]
    fn cancellation_after_the_final_digit_discards_the_pass() {
        let mut digit_boundaries = 0;

        let result = solve_200_9_cancellable(
            b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
            || Some([0; 32]),
            |point| {
                if point == CancellationPoint::DigitBoundary {
                    digit_boundaries += 1;
                }
                digit_boundaries == 10
            },
        );

        assert_eq!(result.outcome(), &CancellableSolveOutcome::Cancelled);
        assert_eq!(result.passes_completed(), 0);
        assert_eq!(result.passes_abandoned(), 1);
    }

    #[test]
    #[allow(unsafe_code)]
    fn a_completed_pass_is_stable_after_an_abandoned_pass() {
        let p = Params::new(200, 9).expect("valid parameters");
        let mut state = verify::initialise_state(p.n, p.k, p.hash_output());
        state.update(b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.");
        state.update(&[0; 32]);

        // SAFETY: the callbacks and parameters match the compiled 200,9 solver.
        let eq = unsafe {
            equi_new(
                blake2b::blake2b_clone,
                blake2b::blake2b_free,
                blake2b::blake2b_update,
                blake2b::blake2b_finalize,
            )
        };

        let baseline = unsafe { worker(eq, p, &state, &mut |_| false) };
        let WorkerOutcome::Completed(baseline) = baseline else {
            unreachable!("the callback never cancels")
        };

        for cancellation_check in [2, 4, 6, 8] {
            let mut checks = 0;
            let abandoned = unsafe {
                worker(eq, p, &state, &mut |point| {
                    if point == CancellationPoint::DigitBoundary {
                        checks += 1;
                    }
                    checks == cancellation_check
                })
            };
            assert!(matches!(abandoned, WorkerOutcome::Cancelled));

            let completed = unsafe { worker(eq, p, &state, &mut |_| false) };
            let WorkerOutcome::Completed(completed) = completed else {
                unreachable!("the callback never cancels")
            };
            assert_eq!(completed, baseline);
        }

        // SAFETY: `eq` is valid and is not used after this call.
        unsafe { equi_free(eq) };
    }
}
