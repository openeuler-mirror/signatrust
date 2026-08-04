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

use lazy_static::lazy_static;
use prometheus::{Encoder, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};

lazy_static! {
    pub static ref REGISTRY: Registry =
        Registry::new_custom(Some("signatrust".into()), None).expect("create metrics registry");

    // ── Sign metrics ──
    pub static ref SIGN_REQUESTS_TOTAL: IntCounter = {
        let m = IntCounter::new(
            "sign_requests_total",
            "Total number of sign requests processed"
        ).expect("create sign_requests_total");
        REGISTRY.register(Box::new(m.clone())).expect("register sign_requests_total");
        m
    };

    pub static ref SIGN_ERRORS_TOTAL: IntCounter = {
        let m = IntCounter::new(
            "sign_errors_total",
            "Total number of sign request errors"
        ).expect("create sign_errors_total");
        REGISTRY.register(Box::new(m.clone())).expect("register sign_errors_total");
        m
    };

    pub static ref SIGN_DURATION_SECONDS: prometheus::Histogram = {
        let m = prometheus::Histogram::with_opts(
            HistogramOpts::new("sign_duration_seconds", "Sign request latency in seconds")
                .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0])
        ).expect("create sign_duration_seconds");
        REGISTRY.register(Box::new(m.clone())).expect("register sign_duration_seconds");
        m
    };

    // ── Cache metrics ──
    pub static ref KEY_CACHE_HIT_TOTAL: IntCounter = {
        let m = IntCounter::new(
            "key_cache_hit_total",
            "Number of key cache hits"
        ).expect("create key_cache_hit_total");
        REGISTRY.register(Box::new(m.clone())).expect("register key_cache_hit_total");
        m
    };

    pub static ref KEY_CACHE_MISS_TOTAL: IntCounter = {
        let m = IntCounter::new(
            "key_cache_miss_total",
            "Number of key cache misses"
        ).expect("create key_cache_miss_total");
        REGISTRY.register(Box::new(m.clone())).expect("register key_cache_miss_total");
        m
    };

    pub static ref KEY_CACHE_SIZE: IntGauge = {
        let m = IntGauge::new(
            "key_cache_size",
            "Current number of entries in the key cache"
        ).expect("create key_cache_size");
        REGISTRY.register(Box::new(m.clone())).expect("register key_cache_size");
        m
    };

    // ── DB pool metrics ──
    pub static ref DB_POOL_CONNECTIONS_IDLE: prometheus::Gauge = {
        let m = prometheus::Gauge::new(
            "db_pool_connections_idle",
            "Number of idle database connections"
        ).expect("create db_pool_connections_idle");
        REGISTRY.register(Box::new(m.clone())).expect("register db_pool_connections_idle");
        m
    };

    pub static ref DB_POOL_CONNECTIONS_USED: prometheus::Gauge = {
        let m = prometheus::Gauge::new(
            "db_pool_connections_used",
            "Number of used database connections"
        ).expect("create db_pool_connections_used");
        REGISTRY.register(Box::new(m.clone())).expect("register db_pool_connections_used");
        m
    };

    // ── gRPC metrics ──
    pub static ref GRPC_REQUESTS_TOTAL: IntCounter = {
        let m = IntCounter::new(
            "grpc_requests_total",
            "Total gRPC requests received"
        ).expect("create grpc_requests_total");
        REGISTRY.register(Box::new(m.clone())).expect("register grpc_requests_total");
        m
    };

    pub static ref GRPC_REQUESTS_INFLIGHT: IntGauge = {
        let m = IntGauge::new(
            "grpc_requests_inflight",
            "Number of gRPC requests currently in flight"
        ).expect("create grpc_requests_inflight");
        REGISTRY.register(Box::new(m.clone())).expect("register grpc_requests_inflight");
        m
    };
}

/// Gather all registered metrics in Prometheus text exposition format.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buf = vec![];
    encoder
        .encode(&REGISTRY.gather(), &mut buf)
        .expect("encode metrics");
    String::from_utf8(buf).expect("metrics as utf8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_requests_counter_increments() {
        let before = gather_metrics();
        SIGN_REQUESTS_TOTAL.inc();
        SIGN_REQUESTS_TOTAL.inc();
        let after = gather_metrics();
        // Metric names are prefixed with "signatrust_" by the registry
        assert!(after.contains("signatrust_sign_requests_total"));
        assert_ne!(before, after);
    }

    #[test]
    fn test_sign_errors_counter_visible() {
        SIGN_ERRORS_TOTAL.inc();
        let metrics = gather_metrics();
        assert!(metrics.contains("signatrust_sign_errors_total"));
    }

    #[test]
    fn test_cache_counters_visible() {
        KEY_CACHE_HIT_TOTAL.inc();
        KEY_CACHE_MISS_TOTAL.inc();
        let metrics = gather_metrics();
        assert!(metrics.contains("signatrust_key_cache_hit_total"));
        assert!(metrics.contains("signatrust_key_cache_miss_total"));
    }

    #[test]
    fn test_gauges_visible() {
        DB_POOL_CONNECTIONS_IDLE.set(5.0);
        KEY_CACHE_SIZE.set(10);
        let metrics = gather_metrics();
        assert!(metrics.contains("signatrust_db_pool_connections_idle 5"));
        assert!(metrics.contains("signatrust_key_cache_size 10"));
    }
}
