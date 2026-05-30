use rustc_hash::FxHasher;
use std::hash::Hasher;

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u8,
}

impl BloomFilter {
    pub fn new(num_bits: usize, num_hashes: u8) -> Self {
        let words = (num_bits + 63) / 64;
        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes,
        }
    }

    pub fn insert(&mut self, item: &str) {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes as u64 {
            let idx = ((h1.wrapping_add(i.wrapping_mul(h2))) % self.num_bits as u64) as usize;
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    pub fn maybe_contains(&self, item: &str) -> bool {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes as u64 {
            let idx = ((h1.wrapping_add(i.wrapping_mul(h2))) % self.num_bits as u64) as usize;
            if self.bits[idx / 64] & (1u64 << (idx % 64)) == 0 {
                return false;
            }
        }
        true
    }

    fn hash_pair(&self, item: &str) -> (u64, u64) {
        let mut h = FxHasher::default();
        h.write(item.as_bytes());
        let hash1 = h.finish();

        let mut h2 = FxHasher::default();
        h2.write(item.as_bytes());
        h2.write_u8(0xff); // salt for second hash
        let hash2 = h2.finish();

        (hash1, hash2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(100, 4);
        assert!(!filter.maybe_contains("google.com"));
        assert!(!filter.maybe_contains("apple.com"));

        filter.insert("google.com");
        assert!(filter.maybe_contains("google.com"));
        assert!(!filter.maybe_contains("apple.com"));

        filter.insert("apple.com");
        assert!(filter.maybe_contains("google.com"));
        assert!(filter.maybe_contains("apple.com"));
    }
}
