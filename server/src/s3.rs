//! SeaweedFS S3 client + presigned upload/download URLs — owned by S5.
//!
//! The Instance talks to SeaweedFS's S3 gateway (aws-sdk-s3 1.x) with static
//! credentials and path-style addressing (`http://host:8333/<bucket>/<key>`).
//! Bytes are client-side ciphertext; the Instance only ever mints signed
//! URLs and (once, at boot) creates the bucket.
//!
//! Presigning is purely local: SigV4 signing with the static credentials
//! happens offline — no request to SeaweedFS is made until the *client*
//! exercises the signed URL. The signed URL carries no Content-Type
//! constraint, so clients PUT raw bytes with whatever (or no) Content-Type.

use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::{Client, Config as S3Config};

use crate::config::Config;
use crate::db::AppState;
use crate::error::{ApiError, ApiResult};

/// Signature region. SeaweedFS ignores it apart from SigV4 verification,
/// which needs *some* region; `us-east-1` is the S3 default everywhere.
const S3_REGION: &str = "us-east-1";

/// Bucket-creation success is cached here: the check runs once per process
/// (failures are NOT cached — a temporarily-down SeaweedFS only delays the
/// first attachment, it never poisons the process).
static BUCKET_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Build a path-style S3 client against the configured SeaweedFS endpoint.
/// `BehaviorVersion::latest()` is set explicitly because we build the SDK
/// config by hand (no aws-config defaults) — the SDK panics without it.
pub fn client(config: &Config) -> Client {
    let s3 = S3Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(&config.s3_endpoint)
        .credentials_provider(Credentials::new(
            &config.s3_access_key,
            &config.s3_secret_key,
            None,
            None,
            "bysyc-static",
        ))
        .region(Region::new(S3_REGION))
        .force_path_style(true)
        .build();
    Client::from_conf(s3)
}

/// Ensure the attachment bucket exists, at most once per process.
///
/// "Bucket already exists" (ours or a namesake's) counts as success: the
/// goal is only that `PUT/GET <bucket>/att/<hex>` can succeed.
pub async fn ensure_bucket(state: &AppState) -> ApiResult<()> {
    BUCKET_READY
        .get_or_try_init(|| async {
            let bucket = &state.config.s3_bucket;
            match client(&state.config)
                .create_bucket()
                .bucket(bucket)
                .send()
                .await
            {
                Ok(_) => {
                    tracing::info!(bucket, "created S3 bucket");
                    Ok(())
                }
                Err(e) => {
                    let already = e
                        .as_service_error()
                        .map(|svc| {
                            svc.is_bucket_already_owned_by_you() || svc.is_bucket_already_exists()
                        })
                        .unwrap_or(false)
                        || e.to_string().to_lowercase().contains("already exist");
                    if already {
                        Ok(())
                    } else {
                        tracing::error!(bucket, "bucket creation failed: {e}");
                        Err(ApiError::internal("object storage unavailable"))
                    }
                }
            }
        })
        .await
        .map(|_| ())
}

/// Presign an object `PUT` (offline; the URL authorizes the client's raw
/// body upload — Content-Type is deliberately not part of the signature).
pub async fn presign_put(state: &AppState, key: &str, expires: Duration) -> ApiResult<String> {
    sign(state, key, expires, true).await
}

/// Presign an object `GET` (offline).
pub async fn presign_get(state: &AppState, key: &str, expires: Duration) -> ApiResult<String> {
    sign(state, key, expires, false).await
}

async fn sign(state: &AppState, key: &str, expires: Duration, put: bool) -> ApiResult<String> {
    let config = PresigningConfig::expires_in(expires)
        .map_err(|e| ApiError::internal(format!("invalid presign expiry: {e}")))?;
    let client = client(&state.config);
    // The two builders carry distinct error types; map each to ApiError so
    // the branches agree on `PresignedRequest`.
    let presigned = if put {
        client
            .put_object()
            .bucket(&state.config.s3_bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(signing_failure(key))?
    } else {
        client
            .get_object()
            .bucket(&state.config.s3_bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(signing_failure(key))?
    };
    Ok(presigned.uri().to_string())
}

fn signing_failure<E: std::fmt::Display>(key: &str) -> impl FnOnce(E) -> ApiError + use<'_, E> {
    move |e| {
        tracing::error!(key, "presigning failed: {e}");
        ApiError::internal("could not sign object url")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_expiry_construction() {
        // The only fallible, non-I/O step: PresigningConfig rejects > 7 days.
        assert!(PresigningConfig::expires_in(Duration::from_secs(15 * 60)).is_ok());
        assert!(PresigningConfig::expires_in(Duration::from_secs(10 * 60)).is_ok());
        assert!(PresigningConfig::expires_in(Duration::from_secs(8 * 24 * 3600)).is_err());
    }
}
