//! ZK deployment loading (design §8.3): the circuit catalog and the
//! rulebooks. Config-driven — new rulebooks and new circuit versions are
//! data; the code is the engine.

use std::path::Path;

use siros_issuer_core::zk::circuit::CircuitManifest;
use siros_issuer_core::{Error, Result};

/// Load the circuit manifest from a static fixture directory (air-gapped
/// and test mode): every `*.json` file is a [`CircuitManifest`]; the
/// circuits merge in file order. Live registry mirrors land behind this
/// same type (`Option<Arc<CircuitManifest>>` on the state), so the
/// resolution semantics never change with the source.
pub fn load_circuit_manifest(static_dir: &Path) -> Result<CircuitManifest> {
    let entries = std::fs::read_dir(static_dir).map_err(|e| {
        Error::configuration(format!(
            "zk.circuits.static_dir {}: {e}",
            static_dir.display()
        ))
    })?;
    let mut manifest = CircuitManifest::default();
    let mut files = 0;
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            Error::configuration(format!("zk circuit manifest {}: {e}", path.display()))
        })?;
        let parsed: CircuitManifest = serde_json::from_str(&text).map_err(|e| {
            Error::configuration(format!("zk circuit manifest {}: {e}", path.display()))
        })?;
        files += 1;
        manifest.circuits.extend(parsed.circuits);
    }
    if files == 0 {
        return Err(Error::configuration(format!(
            "zk.circuits.static_dir {} contains no circuit manifest JSON files",
            static_dir.display()
        )));
    }
    Ok(manifest)
}
