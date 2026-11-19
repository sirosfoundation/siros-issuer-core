//! OpenTelemetry-line telemetry (gap 5, design §12.2's v2 infra item):
//! the observability spine — structured, env-filtered `tracing` logs plus
//! spans on the issuance surfaces, with the PII discipline the audit
//! established (§13.3): spans and events carry IDENTIFIERS only (session
//! ids, offer ids, state labels) — never claim values, never proof
//! material, never token material.
//!
//! The shape:
//! - `[telemetry]` config: absent ⇒ the default subscriber (EnvFilter,
//!   `RUST_LOG` or `info`), no exporter — the conformance profile's
//!   surface is unchanged, stdout carries what `eprintln!` used to.
//! - `[telemetry] otlp_endpoint = "http://collector:4317"` (with the
//!   `otlp` build feature) ⇒ an OTLP/gRPC trace exporter alongside the
//!   logs, spans flowing to the collector. The exporter stack is
//!   FEATURE-gated so the default build carries none of its weight.
//!
//! The init is fallible-soft: telemetry must never kill the service; a
//! failed exporter init logs the failure and serves with logs only.

use siros_issuer_core::{Error, Result};

/// `[telemetry]` — the observability config (gap 5).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCfg {
    /// The OTLP/gRPC collector endpoint (e.g. `http://localhost:4317`).
    /// Absent ⇒ no exporter (logs only — the default posture).
    /// REQUIRES the `otlp` build feature; without it the endpoint is
    /// refused at startup (fail-visible, not silent-ignore).
    pub otlp_endpoint: Option<String>,
    /// The service name on the OTLP resource (default: the binary).
    pub service_name: Option<String>,
}

/// The initialized telemetry guard: dropping it flushes the exporter.
pub struct Telemetry {
    _guard: Option<GuardInner>,
}

enum GuardInner {
    #[cfg(feature = "otlp")]
    // The guard's Drop flushes the exporter; the field is read there.
    #[allow(dead_code)]
    Otlp(otlp::Guard),
    LogsOnly,
}

#[cfg(feature = "otlp")]
mod otlp {
    /// The OTLP exporter guard: flushing on drop.
    pub struct Guard {
        pub provider: opentelemetry_sdk::trace::SdkTracerProvider,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            // Flush: the batch exporter's shutdown drains pending
            // spans (0.29: inherent on the SdkTracerProvider).
            let _ = self.provider.shutdown();
        }
    }
}

/// Initialize telemetry per the config. Call once, before the server
/// binds. A failed OTLP init downgrades to logs-only (never fatal);
/// an endpoint without the `otlp` feature refuses (fail-visible).
pub fn init(cfg: &TelemetryCfg) -> Result<Telemetry> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .map_err(|e| Error::configuration(format!("RUST_LOG: {e}")))?;

    // The OTLP arm: the feature-gated exporter.
    #[cfg(feature = "otlp")]
    {
        if let Some(endpoint) = &cfg.otlp_endpoint {
            use opentelemetry_otlp::WithExportConfig as _;
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| Error::configuration(format!("otlp exporter: {e}")))?;
            let resource = opentelemetry_sdk::Resource::builder()
                .with_service_name(
                    cfg.service_name
                        .clone()
                        .unwrap_or_else(|| "siros-issuer-service".to_owned()),
                )
                .build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build();
            let otel_layer = tracing_opentelemetry::layer().with_tracer(
                opentelemetry::trace::TracerProvider::tracer(&provider, "siros-issuer"),
            );
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();
            return Ok(Telemetry {
                _guard: Some(GuardInner::Otlp(otlp::Guard { provider })),
            });
        }
    }

    // The endpoint is configured but the feature is off: refuse —
    // a deployment that THINKS it exports must learn it does not.
    #[cfg(not(feature = "otlp"))]
    if let Some(_endpoint) = &cfg.otlp_endpoint {
        return Err(Error::configuration(
            "telemetry.otlp_endpoint is configured but the otlp build feature is off — \\
             rebuild with --features otlp or drop the endpoint",
        ));
    }

    // Logs only (the default posture).
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
    Ok(Telemetry {
        _guard: Some(GuardInner::LogsOnly),
    })
}
