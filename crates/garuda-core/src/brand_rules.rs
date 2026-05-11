use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BrandCategory {
    Bank,
    Fintech,
    Telecom,
    Social,
    Ecommerce,
    Government,
    Crypto,
    SaaS,
    Tech,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandRule {
    pub canonical: String,
    pub domain: String,
    pub aliases: Vec<String>,
    pub category: BrandCategory,
    pub risk: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandRulesFile {
    pub version: String,
    #[serde(default)]
    pub checksum: Option<String>,
    pub rules: Vec<BrandRule>,
}

#[derive(Debug, Clone)]
pub struct BrandRules {
    pub version: String,
    pub rules: Vec<BrandRule>,
    pub source_path: PathBuf,
    pub last_modified: Option<SystemTime>,
}

#[derive(Debug)]
struct BrandRulesState {
    rules: BrandRules,
    last_update_check: Option<SystemTime>,
}

static BRAND_RULES: OnceLock<RwLock<BrandRulesState>> = OnceLock::new();

pub fn get_rules() -> BrandRules {
    let state_lock = BRAND_RULES.get_or_init(|| {
        let rules = load_rules_with_update();
        RwLock::new(BrandRulesState {
            rules,
            last_update_check: Some(SystemTime::now()),
        })
    });

    if let Ok(mut state) = state_lock.write() {
        if should_check_updates(state.last_update_check) {
            state.last_update_check = Some(SystemTime::now());
            if let Some(updated) = maybe_update_from_remote() {
                state.rules = updated;
            }
        }

        if should_hot_reload() {
            if let Some(updated) = reload_if_modified(&state.rules) {
                state.rules = updated;
            }
        }

        return state.rules.clone();
    }

    load_rules_with_update()
}

fn should_hot_reload() -> bool {
    std::env::var("GARUDA_BRANDS_HOT_RELOAD")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn should_check_updates(last_check: Option<SystemTime>) -> bool {
    let interval = update_interval();
    if interval.is_zero() {
        return false;
    }

    match last_check {
        Some(last) => SystemTime::now().duration_since(last).unwrap_or_default() >= interval,
        None => true,
    }
}

fn update_interval() -> Duration {
    let secs = std::env::var("GARUDA_BRANDS_UPDATE_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(86_400);

    Duration::from_secs(secs)
}

fn load_rules_with_update() -> BrandRules {
    if let Some(updated) = maybe_update_from_remote() {
        return updated;
    }

    load_rules_from_path(&rules_path()).unwrap_or_else(empty_rules)
}

fn maybe_update_from_remote() -> Option<BrandRules> {
    let url = std::env::var("GARUDA_BRANDS_URL").ok()?;
    let cache_path = cache_path();
    let local_version = load_rules_from_path(&cache_path).map(|rules| rules.version);

    let remote = fetch_rules(&url)?;
    if let Some(checksum) = &remote.checksum {
        if checksum != &checksum_rules(&remote.rules) {
            return None;
        }
    }

    let should_write = local_version
        .as_deref()
        .map(|version| compare_versions(&remote.version, version) == std::cmp::Ordering::Greater)
        .unwrap_or(true);

    if should_write {
        if let Err(_) = write_rules_file(&cache_path, &remote) {
            return None;
        }
    }

    load_rules_from_path(&cache_path).or_else(|| load_rules_from_path(&rules_path()))
}

fn reload_if_modified(existing: &BrandRules) -> Option<BrandRules> {
    let metadata = fs::metadata(&existing.source_path).ok()?;
    let modified = metadata.modified().ok()?;
    if existing.last_modified.map(|ts| ts < modified).unwrap_or(true) {
        return load_rules_from_path(&existing.source_path);
    }
    None
}

fn fetch_rules(url: &str) -> Option<BrandRulesFile> {
    let response = ureq::get(url).call().ok()?;
    let body = response.into_string().ok()?;
    serde_json::from_str::<BrandRulesFile>(&body).ok()
}

fn rules_path() -> PathBuf {
    if let Ok(path) = std::env::var("GARUDA_BRANDS_PATH") {
        return PathBuf::from(path);
    }

    PathBuf::from("lists/brands.json")
}

fn cache_path() -> PathBuf {
    if let Ok(path) = std::env::var("GARUDA_BRANDS_CACHE_PATH") {
        return PathBuf::from(path);
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache/garuda/brands.json");
    }

    PathBuf::from(".garuda/brands.json")
}

fn write_rules_file(path: &Path, rules: &BrandRulesFile) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(rules)?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, json)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn load_rules_from_path(path: &Path) -> Option<BrandRules> {
    let contents = fs::read_to_string(path).ok()?;
    let parsed = serde_json::from_str::<BrandRulesFile>(&contents).ok()?;

    if let Some(checksum) = &parsed.checksum {
        if checksum != &checksum_rules(&parsed.rules) {
            return None;
        }
    }

    let metadata = fs::metadata(path).ok();
    let modified = metadata.and_then(|meta| meta.modified().ok());

    Some(BrandRules {
        version: parsed.version,
        rules: parsed.rules,
        source_path: path.to_path_buf(),
        last_modified: modified,
    })
}

fn checksum_rules(rules: &[BrandRule]) -> String {
    let json = serde_json::to_vec(rules).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = parse_version(left);
    let right_parts = parse_version(right);
    left_parts.cmp(&right_parts)
}

fn parse_version(value: &str) -> (u64, u64, u64) {
    let mut parts = value.split('.').map(|part| part.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch)
}

fn empty_rules() -> BrandRules {
    BrandRules {
        version: "0.0.0".to_string(),
        rules: Vec::new(),
        source_path: rules_path(),
        last_modified: None,
    }
}
