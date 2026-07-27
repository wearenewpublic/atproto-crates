//! Resource limits for data validation.
//!
//! Data validation follows `ref` and `union` indirections while walking a
//! value. Those indirections are driven by the *lexicon*, not by the size of
//! the input document, so a hostile (or merely pathological) lexicon can make
//! validation recurse without consuming any input. [`ValidationLimits`] bounds
//! both the live recursion depth (stack safety) and the total number of
//! indirections followed (CPU safety).
//!
//! The traversal budget is deliberately *proportional* to the document being
//! validated: a fixed allowance ([`ValidationLimits::max_ref_steps`]) plus a
//! per-value-node allowance ([`ValidationLimits::max_ref_steps_per_node`]). An
//! absolute step count would either be small enough to reject ordinary large
//! records — a 200 KB record holding 100,000 integers behind a `ref` costs
//! 100,000 hops — or large enough to hand a tiny hostile body real CPU. The
//! proportional form bounds amplification rather than document size.

/// Default maximum number of simultaneously active `ref`/`union` indirections.
///
/// Chosen to match the `max_depth` convention used by the DRISL decoder in
/// `atproto-dasl`. Each hop costs roughly 3.3 KiB of stack in an unoptimized
/// build, so 256 hops is under 1 MiB and fits comfortably inside a 2 MiB Tokio
/// worker stack; measured aborts start near 650 hops on that stack. Because
/// `serde_json` refuses to parse JSON nested deeper than 128 levels, this
/// budget still allows two indirections at every level of the deepest document
/// that can arrive over the wire.
pub const DEFAULT_MAX_REF_DEPTH: usize = 256;

/// Default number of `ref`/`union` traversals granted to every validation
/// regardless of input size.
///
/// A union without a `$type` discriminator tries every candidate against the
/// same value, so nested unions explore `refs^depth` combinations. This is the
/// part of the budget an attacker gets "for free" from a tiny body: at the
/// measured cost of roughly a quarter of a microsecond per hop, 100,000
/// traversals is on the order of 25 ms no matter how the lexicon is shaped.
///
/// This allowance alone does **not** scale with the document, so it must not be
/// the whole budget — see [`DEFAULT_MAX_REF_STEPS_PER_NODE`].
pub const DEFAULT_MAX_REF_STEPS: usize = 100_000;

/// Default number of additional `ref`/`union` traversals granted per value node
/// in the validated document.
///
/// Legitimate work is proportional to the input: one hop per `ref` that wraps a
/// value, plus one candidate attempt per branch of a `$type`-less union. A
/// four-branch open union at every element of an array therefore costs about
/// five traversals per element. 16 leaves room for unions with roughly a dozen
/// branches, or for a few chained `ref` indirections, at *every* node of a
/// maximum-size (~1 MB) AT Protocol record.
///
/// Because the allowance is proportional, it grants no amplification: a hostile
/// lexicon still cannot make a small body cost more than
/// [`DEFAULT_MAX_REF_STEPS`], and total work stays linear in the size of the
/// document the caller already accepted. Callers that validate very large
/// untrusted documents can tighten it with
/// [`ValidationLimits::with_max_ref_steps_per_node`].
pub const DEFAULT_MAX_REF_STEPS_PER_NODE: usize = 16;

/// Resource limits applied to a single data validation call.
///
/// Use [`ValidationLimits::default`] for the standard budget, or the builder
/// methods to widen or tighten it for a specific caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum number of `ref`/`union` indirections active at once.
    ///
    /// Bounds native stack usage. Exceeding it produces
    /// [`DataValidationError::RefDepthExceeded`](crate::validation::data_errors::DataValidationError::RefDepthExceeded).
    pub max_ref_depth: usize,

    /// Number of `ref`/`union` indirections allowed regardless of input size.
    ///
    /// This is the fixed part of the CPU budget for one validation call; the
    /// proportional part comes from [`ValidationLimits::max_ref_steps_per_node`].
    /// Exhausting the total produces
    /// [`DataValidationError::RefStepBudgetExhausted`](crate::validation::data_errors::DataValidationError::RefStepBudgetExhausted).
    pub max_ref_steps: usize,

    /// Additional `ref`/`union` indirections allowed per value node in the
    /// validated document.
    ///
    /// Keeps the budget proportional to the input so that ordinary large
    /// records are not rejected, while still denying amplification to small
    /// hostile bodies. Set to `0` to make [`ValidationLimits::max_ref_steps`] an
    /// absolute cap.
    pub max_ref_steps_per_node: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_ref_depth: DEFAULT_MAX_REF_DEPTH,
            max_ref_steps: DEFAULT_MAX_REF_STEPS,
            max_ref_steps_per_node: DEFAULT_MAX_REF_STEPS_PER_NODE,
        }
    }
}

impl ValidationLimits {
    /// Create limits using [`DEFAULT_MAX_REF_DEPTH`], [`DEFAULT_MAX_REF_STEPS`]
    /// and [`DEFAULT_MAX_REF_STEPS_PER_NODE`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of simultaneously active `ref`/`union` hops.
    pub fn with_max_ref_depth(mut self, depth: usize) -> Self {
        self.max_ref_depth = depth;
        self
    }

    /// Set the number of `ref`/`union` traversals allowed independently of input
    /// size.
    pub fn with_max_ref_steps(mut self, steps: usize) -> Self {
        self.max_ref_steps = steps;
        self
    }

    /// Set the number of extra `ref`/`union` traversals allowed per value node.
    pub fn with_max_ref_steps_per_node(mut self, steps: usize) -> Self {
        self.max_ref_steps_per_node = steps;
        self
    }

    /// Extra traversal budget earned by a document containing `node_count` values.
    ///
    /// This is an increment, not a total. A procedure validates its params and its input
    /// against a single context, so each document adds its own allowance on top of the
    /// starting [`Self::max_ref_steps`] rather than replacing it.
    ///
    /// Saturates instead of overflowing, so an enormous node count simply
    /// yields `usize::MAX`.
    pub fn step_allowance_for(&self, node_count: usize) -> usize {
        self.max_ref_steps_per_node.saturating_mul(node_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ValidationLimits::default();
        assert_eq!(limits.max_ref_depth, DEFAULT_MAX_REF_DEPTH);
        assert_eq!(limits.max_ref_steps, DEFAULT_MAX_REF_STEPS);
        assert_eq!(
            limits.max_ref_steps_per_node,
            DEFAULT_MAX_REF_STEPS_PER_NODE
        );
        assert_eq!(limits, ValidationLimits::new());
    }

    #[test]
    fn test_builder_overrides() {
        let limits = ValidationLimits::new()
            .with_max_ref_depth(4)
            .with_max_ref_steps(9)
            .with_max_ref_steps_per_node(3);
        assert_eq!(limits.max_ref_depth, 4);
        assert_eq!(limits.max_ref_steps, 9);
        assert_eq!(limits.max_ref_steps_per_node, 3);
    }

    #[test]
    fn test_step_allowance_is_proportional_to_node_count() {
        let limits = ValidationLimits::new()
            .with_max_ref_steps(10)
            .with_max_ref_steps_per_node(4);
        assert_eq!(limits.step_allowance_for(0), 0);
        assert_eq!(limits.step_allowance_for(1_000), 4_000);

        // A zero per-node allowance turns max_ref_steps into an absolute cap.
        let capped = limits.with_max_ref_steps_per_node(0);
        assert_eq!(capped.step_allowance_for(1_000_000), 0);
    }

    #[test]
    fn test_step_allowance_saturates() {
        let limits = ValidationLimits::new()
            .with_max_ref_steps(usize::MAX)
            .with_max_ref_steps_per_node(usize::MAX);
        assert_eq!(limits.step_allowance_for(usize::MAX), usize::MAX);
    }
}
