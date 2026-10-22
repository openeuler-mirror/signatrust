/*
 *
 *  * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  * //
 *  * // signatrust is licensed under Mulan PSL v2.
 *  * // You can use this software according to the terms and conditions of the Mulan
 *  * // PSL v2.
 *  * // You may obtain a copy of Mulan PSL v2 at:
 *  * //         http://license.coscl.org.cn/MulanPSL2
 *  * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *  * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *  * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *  * // See the Mulan PSL v2 for more details.
 *
 */

use std::time::Duration;

use rand::Rng;

/// Initial backoff in milliseconds for retries on transient remote-call
/// failures.
pub const INITIAL_BACKOFF_MS: u64 = 100;

/// Exponential backoff (base `INITIAL_BACKOFF_MS`, doubling per attempt) plus
/// a random jitter within one initial backoff interval, avoiding retry storms
/// when many callers fail simultaneously.
///
/// `attempt` is 1-based and must be greater than 1 (the first attempt is the
/// initial call, performed without backoff).
pub fn backoff_duration(attempt: u32) -> Duration {
    debug_assert!(attempt > 1, "attempt must be greater than 1");
    let jitter_ms = rand::thread_rng().gen_range(0..INITIAL_BACKOFF_MS);
    Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt - 2) + jitter_ms)
}
