//! Build script: stamps a cache-busting `BUILD_REV` and, under the `embed`
//! feature, embeds the `templates/` directory via `minijinja-embed`. No JS/npm
//! build stage exists — the AppView is server-rendered HTML only.

fn main() {
    println!("cargo:rerun-if-changed=templates");

    // Generate build revision for cache busting.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    let hash = hasher.finish();
    let rev = format!("{:012x}", hash & 0xffff_ffff_ffff);

    println!("cargo:rustc-env=BUILD_REV={}", rev);

    #[cfg(feature = "embed")]
    {
        use std::env;
        use std::path::PathBuf;
        let template_path = if let Ok(value) = env::var("HTTP_TEMPLATE_PATH") {
            value
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("templates")
                .display()
                .to_string()
        };
        minijinja_embed::embed_templates!(&template_path);
    }
}
