//! S3 layout shared by the deployer's commands (commonware `deployer::aws::s3`): the key
//! prefixes, presigning duration, and the `wget` invocation instances download with.

/// File in the deployer directory that holds the shared bucket's name.
pub const bucket_config_file = "bucket";

/// Prefix for cached tool binaries and images.
pub const tools_binaries_prefix = "tools/binaries";
/// Prefix for cached static configs and service files.
pub const tools_configs_prefix = "tools/configs";
/// Prefix for per-deployment files.
pub const deployments_prefix = "deployments";

/// Largest buffer used when hashing a file for its content digest.
pub const max_hash_buffer_size: usize = 32 * 1024 * 1024;
/// Most files hashed at once.
pub const max_concurrent_hashes: usize = 8;
/// How long presigned URLs stay valid.
pub const presign_duration_s: u64 = 6 * 60 * 60;

/// `wget` with retries on connection failures and on HTTP 404 (S3 eventual consistency),
/// 408, 429, 500, 502, 503, and 504.
pub const wget = "wget -q --tries=10 --retry-connrefused " ++
    "--retry-on-http-error=404,408,429,500,502,503,504 --waitretry=5";
