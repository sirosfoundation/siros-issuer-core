//! The shared-replica rate counter (§11): MongoDB `find_one_and_update`
//! `$inc` — one budget per (endpoint, client, window) **across
//! replicas**, the contract vc's shared-cache counter serves in its
//! deployments. Fail-closed: a Mongo error is 503, never an open
//! window (the in-process counter's semantics, preserved).
//!
//! Windowing: fixed 60-second buckets keyed by the bucket's start
//! (`floor(now/60)`), so every replica agrees on the window without
//! coordination; expired windows die by a TTL index on `window_end`
//! (MongoDB expires them lazily — the counter never reads them again
//! either way, the id pins the bucket).

use mongodb::bson::{doc, Document};
use mongodb::options::{CreateIndexOptions, FindOneAndUpdateOptions, IndexOptions, ReturnDocument};
use siros_issuer_core::{Error, Result};

use crate::rate_limit::RateCounter;

const WINDOW_SECS: i64 = 60;

/// One endpoint's shared budget. Clone-safe: the collection handle is
/// internally shared; the limit rides the endpoint's counter.
#[derive(Clone)]
pub struct MongoRateCounter {
    collection: mongodb::Collection<Document>,
    requests_per_minute: u64,
}

impl MongoRateCounter {
    /// Connect one counter over the `rate_limits` collection, creating
    /// the TTL index (idempotent). The counter never touches subject
    /// data — endpoint paths and client IPs only.
    pub async fn connect(
        client: &mongodb::Client,
        database: &str,
        requests_per_minute: u64,
    ) -> Result<Self> {
        let collection = client.database(database).collection("rate_limits");
        // TTL: expire each window's doc just past its end. Best-effort —
        // an index-creation failure refuses startup (a growing counter
        // collection is a slow leak; fail-closed beats creeping debt).
        let index = mongodb::IndexModel::builder()
            .keys(doc! { "window_end": 1 })
            .options(
                IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(0))
                    .name("ttl_window_end".to_owned())
                    .build(),
            )
            .build();
        collection
            .create_index(index)
            .with_options(CreateIndexOptions::builder().build())
            .await
            .map_err(|e| Error::configuration(format!("rate counter ttl index: {e}")))?;
        Ok(Self {
            collection,
            requests_per_minute,
        })
    }
}

#[async_trait::async_trait]
impl RateCounter for MongoRateCounter {
    async fn allow(&self, endpoint: &str, client: &str, now_unix: i64) -> Result<bool> {
        let window_start = now_unix - now_unix.rem_euclid(WINDOW_SECS);
        // The id pins the bucket: (endpoint, client, window). A pipe
        // separates the parts; endpoint paths never carry one.
        let id = format!("{endpoint}|{client}|{window_start}");
        // Upsert + $inc + After-picture in ONE server-side step: two
        // replicas incrementing concurrently both see their own
        // post-count — the budget is shared exactly.
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let updated = self
            .collection
            .find_one_and_update(
                doc! { "_id": &id },
                doc! {
                    "$inc": { "count": 1 },
                    "$setOnInsert": { "window_end": window_start + WINDOW_SECS },
                },
            )
            .with_options(options)
            .await
            .map_err(|e| {
                // Fail-closed (vc's semantics): an unavailable counter
                // is 503, never an open window.
                Error::new(
                    siros_issuer_core::error::code::TRANSPORT,
                    format!("rate counter: {e}"),
                )
            })?;
        // `$inc` mints an int32 on first insert and stays int32; read
        // either width. A missing count is a refusal, never a pass.
        let count = updated
            .and_then(|doc| match doc.get("count") {
                Some(mongodb::bson::Bson::Int32(n)) => Some(*n as i64),
                Some(mongodb::bson::Bson::Int64(n)) => Some(*n),
                _ => None,
            })
            .ok_or_else(|| {
                Error::new(
                    siros_issuer_core::error::code::TRANSPORT,
                    "rate counter: the increment's result did not answer",
                )
            })?;
        Ok(count <= self.requests_per_minute as i64)
    }
}
