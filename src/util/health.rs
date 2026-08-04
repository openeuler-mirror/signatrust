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

use sea_orm::DatabaseConnection;
use serde::Serialize;
use std::time::Instant;

/// Health check result for a single dependency.
#[derive(Debug, Serialize)]
pub struct HealthComponent {
    pub status: String,
    pub latency_ms: u128,
}

impl HealthComponent {
    pub fn up(latency_ms: u128) -> Self {
        HealthComponent {
            status: "UP".into(),
            latency_ms,
        }
    }

    pub fn down(latency_ms: u128) -> Self {
        HealthComponent {
            status: "DOWN".into(),
            latency_ms,
        }
    }
}

/// Aggregated health check response for /ready endpoint.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub checks: HealthChecks,
}

#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub database: HealthComponent,
}

/// Checks only database liveness (avoid KMS/Redis dependency for simplicity).
/// Other checks can be added later without changing the caller signature.
pub async fn check_database(db: &DatabaseConnection) -> HealthComponent {
    let start = Instant::now();
    match db.ping().await {
        Ok(_) => HealthComponent::up(start.elapsed().as_millis()),
        Err(_) => HealthComponent::down(start.elapsed().as_millis()),
    }
}

/// Run all health checks and return the aggregated response.
pub async fn run_health_checks(db: &DatabaseConnection) -> HealthResponse {
    let db_check = check_database(db).await;
    let overall = if db_check.status == "UP" {
        "UP"
    } else {
        "DOWN"
    };

    HealthResponse {
        status: overall.into(),
        checks: HealthChecks { database: db_check },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_component_up() {
        let c = HealthComponent::up(42);
        assert_eq!(c.status, "UP");
        assert_eq!(c.latency_ms, 42);
    }

    #[test]
    fn test_health_component_down() {
        let c = HealthComponent::down(7);
        assert_eq!(c.status, "DOWN");
        assert_eq!(c.latency_ms, 7);
    }

    #[test]
    fn test_health_response_serialization() {
        let resp = HealthResponse {
            status: "UP".into(),
            checks: HealthChecks {
                database: HealthComponent::up(5),
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"UP\""));
        assert!(json.contains("\"database\""));
        assert!(json.contains("\"latency_ms\":5"));
    }
}
