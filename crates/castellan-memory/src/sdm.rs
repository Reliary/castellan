//! Vendored from engfield (MIT, 2026) — the Kanerva Sparse Distributed
//! Memory core (sdm.rs + hash.rs), adapted to castellan-memory's module
//! layout. Attribution: engfield, https://github.com/Reliary/engfield.
//!
//! A 512-bit content-addressable memory: writes activate all locations
//! within a Hamming radius; reads converge by majority vote. The
//! fragment→whole property: a partial cue activates a superset of the
//! full shape's locations, so the converged pattern is preserved.

use std::fmt;

/// A 512-bit SDM address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address([u8; 64]);

impl Address {
  pub fn as_bytes(&self) -> &[u8; 64] {
    &self.0
  }

  pub fn from_bytes(bytes: [u8; 64]) -> Self {
    Self(bytes)
  }
}

impl fmt::Debug for Address {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for b in self.0.iter().take(8) {
      write!(f, "{:02x}", b)?;
    }
    write!(f, "..")
  }
}

/// Hash arbitrary context bytes into a 512-bit address (BLAKE3 keyed).
pub fn hash_context(context: &[u8], key: &[u8; 32]) -> Address {
  let mut hasher = blake3::Hasher::new_keyed(key);
  let mut output = [0u8; 64];
  hasher.update(context).finalize_xof().fill(&mut output);
  Address(output)
}

/// Hamming distance between two 512-bit addresses.
pub fn hamming_distance(a: &Address, b: &Address) -> u32 {
  let mut dist = 0u32;
  for i in 0..8 {
    let chunk_a = u64::from_ne_bytes(a.0[i * 8..i * 8 + 8].try_into().unwrap());
    let chunk_b = u64::from_ne_bytes(b.0[i * 8..i * 8 + 8].try_into().unwrap());
    dist += (chunk_a ^ chunk_b).count_ones();
  }
  dist
}

pub const ADDRESS_BITS: usize = 512;
pub const NUM_LOCATIONS: usize = 65536;
pub const ACTIVATION_RADIUS: u32 = 240;
pub const MIN_ACTIVATIONS: usize = 20;

/// Configuration for the Sparse Distributed Memory.
#[derive(Debug, Clone)]
pub struct SdmConfig {
  pub num_locations: usize,
  pub bits: usize,
  pub activation_radius: u32,
  pub min_activations: usize,
  pub hash_key: [u8; 32],
}

impl Default for SdmConfig {
  fn default() -> Self {
    Self {
      num_locations: NUM_LOCATIONS,
      bits: ADDRESS_BITS,
      activation_radius: ACTIVATION_RADIUS,
      min_activations: MIN_ACTIVATIONS,
      hash_key: [0u8; 32],
    }
  }
}

/// A location in the SDM: one i16 counter per bit.
#[derive(Debug, Clone)]
pub struct Location {
  pub counters: Vec<i16>,
  pub write_count: u64,
  pub address: Address,
}

impl Location {
  pub fn new(bits: usize, index: usize, config: &SdmConfig) -> Self {
    let context = format!("sdm-loc-{}", index);
    let address = hash_context(context.as_bytes(), &config.hash_key);
    Self { counters: vec![0i16; bits], write_count: 0, address }
  }
}

/// The Sparse Distributed Memory matrix.
#[derive(Debug)]
pub struct LocationMatrix {
  pub locations: Vec<Location>,
  pub config: SdmConfig,
}

impl LocationMatrix {
  pub fn new(config: SdmConfig) -> Self {
    let locations = (0..config.num_locations).map(|i| Location::new(config.bits, i, &config)).collect();
    Self { locations, config }
  }

  /// Write a 512-bit pattern at the given address: all locations within
  /// the activation radius get counters incremented (bit=1) or
  /// decremented (bit=0).
  pub fn write(&mut self, address: &Address, pattern: &Address) {
    let radius = self.config.activation_radius;
    let pbytes = pattern.as_bytes();
    for loc in self.locations.iter_mut() {
      let dist = hamming_distance(address, &loc.address);
      if dist <= radius {
        for bit in 0..self.config.bits {
          let byte_idx = bit / 8;
          let bit_idx = bit % 8;
          let bit_val = (pbytes[byte_idx] >> bit_idx) & 1;
          if bit_val == 1 {
            loc.counters[bit] = loc.counters[bit].saturating_add(1).min(i16::MAX - 1);
          } else {
            loc.counters[bit] = loc.counters[bit].saturating_sub(1).max(i16::MIN + 1);
          }
        }
        loc.write_count += 1;
      }
    }
  }

  /// Read at an address: majority vote over activated locations.
  pub fn read(&self, address: &Address) -> Address {
    let radius = self.config.activation_radius;
    let mut activated: Vec<&Location> = Vec::new();
    for loc in self.locations.iter() {
      if hamming_distance(address, &loc.address) <= radius {
        activated.push(loc);
      }
    }
    if activated.is_empty() {
      return Address::from_bytes([0u8; 64]);
    }
    let mut output = [0u8; 64];
    for bit in 0..self.config.bits {
      let mut sum: i32 = 0;
      for loc in &activated {
        sum += loc.counters[bit] as i32;
      }
      if sum > 0 {
        output[bit / 8] |= 1 << (bit % 8);
      }
    }
    Address::from_bytes(output)
  }

  pub fn total_memories(&self) -> u64 {
    self.locations.iter().map(|l| l.write_count).sum()
  }

  pub fn activation_count(&self, address: &Address) -> usize {
    let radius = self.config.activation_radius;
    self.locations.iter().filter(|loc| hamming_distance(address, &loc.address) <= radius).count()
  }

  /// Locations within the activation radius that have been WRITTEN.
  /// A location with zero writes carries no memory; counting it would
  /// make every address look "activated" (the self-region check bug).
  pub fn written_near(&self, address: &Address) -> usize {
    let radius = self.config.activation_radius;
    self
      .locations
      .iter()
      .filter(|loc| loc.write_count > 0 && hamming_distance(address, &loc.address) <= radius)
      .count()
  }

  pub fn location_slices(&self) -> &[Location] {
    &self.locations
  }

  pub fn location_slices_mut(&mut self) -> &mut [Location] {
    &mut self.locations
  }
}

impl Default for LocationMatrix {
  fn default() -> Self {
    Self::new(SdmConfig::default())
  }
}
