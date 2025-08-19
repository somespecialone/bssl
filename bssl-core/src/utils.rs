use boring2::error::ErrorStack;
use std::ffi::c_int;
use std::{
    cell::Cell,
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    num::Wrapping,
};

// from boring-sys lib.rs
pub fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

// Function below adapted from wreq (https://github.com/0x676e67/wreq)
// Copyright 2025 wreq developers
// Licensed under the Apache License, Version 2.0
//
// https://github.com/0x676e67/wreq/blob/d3d80f16e23e8e1594f2c45041b9403ea2b6be03/src/util.rs#L27
pub fn fast_random() -> u64 {
    thread_local! {
        static RNG: Cell<Wrapping<u64>> = Cell::new(Wrapping(seed()));
    }

    fn seed() -> u64 {
        let seed = RandomState::new();

        let mut out = 0;
        let mut cnt = 0;
        while out == 0 {
            cnt += 1;
            let mut hasher = seed.build_hasher();
            hasher.write_usize(cnt);
            out = hasher.finish();
        }
        out
    }

    RNG.with(|rng| {
        let mut n = rng.get();
        debug_assert_ne!(n.0, 0);
        n ^= n >> 12;
        n ^= n << 25;
        n ^= n >> 27;
        rng.set(n);
        n.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    })
}

pub fn random_bool() -> bool {
    (fast_random() & 1) == 0
}
