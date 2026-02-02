//! PhysJitter: Proof-of-process primitive using timing jitter.
//!
//! This crate provides cryptographic proof-of-process through timing jitter,
//! enabling verification of human authorship in document creation.
//!
//! # Architecture
//!
//! The crate is built around two core traits:
//!
//! - [`EntropySource`]: Collects entropy from hardware or environment
//! - [`JitterEngine`]: Computes jitter delays from secrets and entropy
//!
//! Two implementations are provided:
//!
//! - [`PureJitter`]: HMAC-based, economic security model (works everywhere)
//! - [`PhysJitter`]: Hardware entropy, physics security model (requires hardware)
//!
//! The [`HybridEngine`] automatically selects the best available source.
//!
//! # Example
//!
//! ```rust
//! use physjitter::{HybridEngine, PureJitter, PhysJitter, Evidence};
//!
//! // Create hybrid engine with fallback
//! let engine = HybridEngine::new(PhysJitter::default(), PureJitter::default());
//! let secret = [0u8; 32]; // Your session secret
//!
//! // Sample jitter for each keystroke
//! let inputs = b"keystroke data";
//! let (jitter, evidence) = engine.sample(&secret, inputs).unwrap();
//!
//! // Apply jitter delay
//! std::thread::sleep(std::time::Duration::from_micros(jitter as u64));
//!
//! // Store evidence for later verification
//! println!("Jitter: {}μs, Physics: {}", jitter, evidence.is_phys());
//! ```
//!
//! # Security Models
//!
//! ## Economic Security (PureJitter)
//!
//! Security relies on the economic cost of reproducing the exact input sequence.
//! An attacker would need to retype content character-by-character with identical
//! timing to reproduce the jitter chain.
//!
//! ## Physics Security (PhysJitter)
//!
//! Security relies on hardware entropy that cannot be perfectly simulated.
//! Uses TSC (Time Stamp Counter) and timing variations unique to the physical
//! device.
//!
//! ## Hybrid Security (HybridEngine)
//!
//! Combines both models: uses physics when available, falls back to pure jitter
//! in virtualized environments. Evidence records which mode was used.

use zeroize::Zeroizing;

pub mod evidence;
pub mod model;
pub mod phys;
pub mod pure;
pub mod traits;

// Re-exports
pub use evidence::{Evidence, EvidenceChain};
pub use model::{Anomaly, AnomalyKind, HumanModel, SequenceStats, ValidationResult};
pub use phys::PhysJitter;
pub use pure::PureJitter;
pub use traits::{EntropySource, JitterEngine};

/// Hash output with associated entropy metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhysHash {
    /// SHA-256 hash of the entropy samples and inputs.
    pub hash: [u8; 32],
    /// Estimated entropy bits in the samples.
    pub entropy_bits: u8,
}

impl From<[u8; 32]> for PhysHash {
    fn from(hash: [u8; 32]) -> Self {
        Self {
            hash,
            entropy_bits: 0,
        }
    }
}

/// Jitter delay in microseconds.
pub type Jitter = u32;

/// Error types for physjitter operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Insufficient entropy collected from hardware.
    #[error("Insufficient entropy: required {required} bits, found {found}")]
    InsufficientEntropy { required: u8, found: u8 },

    /// Hardware entropy source not available.
    #[error("Hardware entropy not available: {reason}")]
    HardwareUnavailable { reason: String },

    /// Invalid input provided.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Hybrid engine that combines physics and pure jitter with automatic fallback.
///
/// Uses physics-based entropy when available and valid, falling back to
/// pure HMAC-based jitter in virtualized environments or when hardware
/// entropy is insufficient.
#[derive(Debug, Clone)]
pub struct HybridEngine<P = PhysJitter, F = PureJitter>
where
    P: EntropySource + JitterEngine,
    F: JitterEngine,
{
    /// Physics-based entropy source.
    phys: P,
    /// Fallback jitter engine.
    fallback: F,
    /// Minimum entropy bits required to use physics mode.
    min_phys_entropy: u8,
}

impl Default for HybridEngine<PhysJitter, PureJitter> {
    fn default() -> Self {
        Self::new(PhysJitter::default(), PureJitter::default())
    }
}

impl<P, F> HybridEngine<P, F>
where
    P: EntropySource + JitterEngine,
    F: JitterEngine,
{
    /// Create a new hybrid engine with given physics and fallback engines.
    pub fn new(phys: P, fallback: F) -> Self {
        Self {
            phys,
            fallback,
            min_phys_entropy: 8, // Require at least 8 bits of entropy
        }
    }

    /// Set minimum entropy bits required for physics mode.
    pub fn with_min_entropy(mut self, bits: u8) -> Self {
        self.min_phys_entropy = bits;
        self
    }

    /// Sample jitter using best available source.
    ///
    /// Attempts to use physics-based entropy first. If hardware entropy
    /// is unavailable or insufficient, falls back to pure HMAC-based jitter.
    ///
    /// Returns the jitter delay and evidence of how it was computed.
    pub fn sample(&self, secret: &[u8; 32], inputs: &[u8]) -> Result<(Jitter, Evidence), Error> {
        // Try physics-based entropy first
        match self.phys.sample(inputs) {
            Ok(entropy) if entropy.entropy_bits >= self.min_phys_entropy && self.phys.validate(entropy) => {
                let jitter = self.phys.compute_jitter(secret, inputs, entropy);
                Ok((jitter, Evidence::phys(entropy, jitter)))
            }
            Ok(_) | Err(_) => {
                // Fall back to pure jitter
                let jitter = self.fallback.compute_jitter(secret, inputs, [0u8; 32].into());
                Ok((jitter, Evidence::pure(jitter)))
            }
        }
    }

    /// Check if physics-based entropy is currently available.
    pub fn phys_available(&self) -> bool {
        self.phys.sample(b"probe").is_ok()
    }
}

/// Session manager for tracking jitter evidence over a document editing session.
#[derive(Debug)]
pub struct Session {
    /// Secret key for this session (zeroized on drop).
    secret: Zeroizing<[u8; 32]>,
    /// Hybrid jitter engine.
    engine: HybridEngine,
    /// Accumulated evidence chain.
    evidence: EvidenceChain,
    /// Human typing model for validation.
    model: HumanModel,
}

impl Session {
    /// Create a new session with the given secret.
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            engine: HybridEngine::default(),
            evidence: EvidenceChain::with_secret(secret),
            model: HumanModel::default(),
        }
    }

    /// Create a session with a random secret.
    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::new(secret)
    }

    /// Sample jitter for an input event and record evidence.
    pub fn sample(&mut self, inputs: &[u8]) -> Result<Jitter, Error> {
        let (jitter, evidence) = self.engine.sample(&self.secret, inputs)?;
        self.evidence.append(evidence);
        Ok(jitter)
    }

    /// Get the current evidence chain.
    pub fn evidence(&self) -> &EvidenceChain {
        &self.evidence
    }

    /// Validate the current evidence chain against human typing model.
    pub fn validate(&self) -> ValidationResult {
        let jitters: Vec<Jitter> = self.evidence.records.iter().map(|e| e.jitter()).collect();
        self.model.validate(&jitters)
    }

    /// Get physics coverage ratio for this session.
    pub fn phys_ratio(&self) -> f64 {
        self.evidence.phys_ratio()
    }

    /// Export evidence chain as JSON.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_engine_default() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];
        let inputs = b"test input";

        let result = engine.sample(&secret, inputs);
        assert!(result.is_ok());

        let (jitter, evidence) = result.unwrap();
        assert!(jitter >= 500);
        assert!(jitter < 3000);
        assert!(evidence.jitter() == jitter);
    }

    #[test]
    fn test_session_workflow() {
        let secret = [1u8; 32];
        let mut session = Session::new(secret);

        // Simulate typing
        for i in 0..30 {
            let input = format!("keystroke {}", i);
            let jitter = session.sample(input.as_bytes()).unwrap();
            assert!(jitter >= 500);
        }

        // Check evidence
        assert_eq!(session.evidence().records.len(), 30);

        // Validate against human model
        let validation = session.validate();
        println!("Validation: {:?}", validation);
    }

    #[test]
    fn test_evidence_serialization() {
        let secret = [2u8; 32];
        let mut session = Session::new(secret);

        for i in 0..10 {
            session.sample(format!("key{}", i).as_bytes()).unwrap();
        }

        let json = session.export_json().unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"records\""));
    }

    #[test]
    fn test_pure_jitter_determinism() {
        let engine = PureJitter::default();
        let secret = [99u8; 32];
        let inputs = b"deterministic test";
        let entropy: PhysHash = [0u8; 32].into();

        let j1 = engine.compute_jitter(&secret, inputs, entropy);
        let j2 = engine.compute_jitter(&secret, inputs, entropy);

        assert_eq!(j1, j2, "Pure jitter should be deterministic");
    }

    #[test]
    fn test_empty_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];

        // Empty input should still work
        let result = engine.sample(&secret, b"");
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];

        // Large input should work
        let large_input = vec![0u8; 10000];
        let result = engine.sample(&secret, &large_input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_phys_entropy_enforced() {
        // Create engine with high entropy requirement that will likely fail
        let engine = HybridEngine::default().with_min_entropy(255);
        let secret = [42u8; 32];

        // Should fall back to pure jitter since entropy requirement is impossibly high
        let (_, evidence) = engine.sample(&secret, b"test").unwrap();
        assert!(!evidence.is_phys(), "Should have fallen back to pure jitter");
    }
}
