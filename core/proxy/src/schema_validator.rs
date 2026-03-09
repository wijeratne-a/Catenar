//! Optional JSON Schema validation for request bodies. Prevents LLM hallucinated parameters
//! from reaching upstream APIs (tool poisoning). Opt-in per endpoint.

use anyhow::{Context, Result};
use jsonschema::{Draft, JSONSchema};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::Path;

/// Map: host -> method -> path (prefix or exact) -> compiled schema.
type SchemaMap = HashMap<String, HashMap<String, HashMap<String, JSONSchema>>>;

#[derive(Debug, Default, Deserialize)]
struct RegistryFile {
    /// Map of "host" -> { "METHOD" -> { "path_or_prefix" -> schema } }
    #[serde(default)]
    endpoints: HashMap<String, HashMap<String, HashMap<String, JsonValue>>>,
}

/// Registry of JSON schemas for request body validation. Only validates endpoints with registered schemas.
#[derive(Debug)]
pub struct SchemaRegistry {
    map: SchemaMap,
}

impl SchemaRegistry {
    /// Load schema registry from a JSON file. Format:
    /// `{ "endpoints": { "host": { "POST": { "/v1/chat": { "$schema": "...", "type": "object", ... } } } } }`
    /// Paths are matched by prefix (longest match wins). Empty or missing file = no validation.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read schema registry {}", path.display()))?;
        let reg: RegistryFile = serde_json::from_str(&raw)
            .with_context(|| format!("invalid schema registry JSON in {}", path.display()))?;

        let mut schema_storage = Vec::new();
        let mut entries: Vec<(String, String, String, usize)> = Vec::new();
        for (host, methods) in reg.endpoints {
            let host_lower = host.to_lowercase();
            for (method, paths) in methods {
                let method_upper = method.to_uppercase();
                for (path_key, schema_json) in paths {
                    let idx = schema_storage.len();
                    schema_storage.push(schema_json);
                    entries.push((host_lower.clone(), method_upper.clone(), path_key, idx));
                }
            }
        }

        // JSONSchema::compile requires 'static reference. Leak storage (one-time config load).
        let schema_storage: &'static [JsonValue] = Box::leak(schema_storage.into_boxed_slice());

        let mut map: SchemaMap = HashMap::new();
        for (host, method, path_key, idx) in entries {
            let schema_ref = &schema_storage[idx];
            let compiled = JSONSchema::options()
                .with_draft(Draft::Draft7)
                .compile(schema_ref)
                .with_context(|| format!("invalid schema for {}", path_key))?;
            map.entry(host)
                .or_default()
                .entry(method)
                .or_default()
                .insert(path_key, compiled);
        }
        Ok(Some(Self { map }))
    }

    /// Validate body against the best-matching schema (longest path prefix). Returns Ok(()) if valid or no schema registered.
    /// Returns Err with human-readable validation messages if invalid.
    pub fn validate(
        &self,
        host: &str,
        method: &str,
        path: &str,
        body: &JsonValue,
    ) -> Result<(), Vec<String>> {
        let host_lower = host.to_lowercase();
        let method_upper = method.to_uppercase();
        let method_map = match self.map.get(&host_lower) {
            Some(m) => m,
            None => return Ok(()),
        };
        let path_map = match method_map.get(&method_upper) {
            Some(m) => m,
            None => return Ok(()),
        };

        // Find longest matching path prefix
        let mut best_match: Option<(&str, &JSONSchema)> = None;
        for (registered_path, schema) in path_map.iter() {
            if path == *registered_path
                || path.starts_with(&format!("{}/", registered_path))
                || path.starts_with(registered_path)
            {
                if best_match.map(|(p, _)| p.len()).unwrap_or(0) < registered_path.len() {
                    best_match = Some((registered_path, schema));
                }
            }
        }

        let (_, schema) = match best_match {
            Some(m) => m,
            None => return Ok(()),
        };

        match schema.validate(body) {
            Ok(()) => Ok(()),
            Err(errors) => {
                let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
                Err(messages)
            }
        }
    }
}
