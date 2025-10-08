//! Tokenization engine for secure pattern replacement in vault commands

use regex::Regex;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Token pattern for vault key replacement
pub struct TokenPattern {
    pub original: String,
    pub key_name: String,
    pub start_pos: usize,
    pub end_pos: usize,
}

/// Tokenization engine for secure pattern replacement
pub struct TokenizationEngine {
    pattern_regex: Regex,
}

impl TokenizationEngine {
    /// Create new tokenization engine
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let pattern_regex = Regex::new(r"\{\{\s*([A-Z_][A-Z0-9_]*)\s*\}\}")?;
        Ok(Self { pattern_regex })
    }

    /// Find all token patterns in command arguments
    pub fn find_patterns(&self, args: &[String]) -> Vec<TokenPattern> {
        let mut patterns = Vec::new();

        for arg in args.iter() {
            for capture in self.pattern_regex.captures_iter(arg) {
                if let (Some(full_match), Some(key_name)) = (capture.get(0), capture.get(1)) {
                    patterns.push(TokenPattern {
                        original: full_match.as_str().to_string(),
                        key_name: key_name.as_str().to_string(),
                        start_pos: full_match.start(),
                        end_pos: full_match.end(),
                    });
                }
            }
        }

        patterns
    }

    /// Replace patterns with vault values
    pub fn replace_patterns(
        &self,
        args: &[String],
        vault_values: &HashMap<String, String>,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();

        for arg in args {
            let mut replaced_arg = arg.clone();

            // Replace all patterns in this argument
            for capture in self.pattern_regex.captures_iter(arg) {
                if let (Some(full_match), Some(key_name)) = (capture.get(0), capture.get(1)) {
                    let key = key_name.as_str();

                    if let Some(value) = vault_values.get(key) {
                        replaced_arg = replaced_arg.replace(full_match.as_str(), value);
                    } else {
                        return Err(format!("Key '{}' not found in vault", key).into());
                    }
                }
            }

            result.push(replaced_arg);
        }

        Ok(result)
    }
}

/// Secure string wrapper that zeroizes on drop
#[derive(Clone)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_detection() {
        let engine = TokenizationEngine::new().unwrap();
        let args = vec!["echo".to_string(), "{{ API_KEY }}".to_string()];
        let patterns = engine.find_patterns(&args);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].key_name, "API_KEY");
    }

    #[test]
    fn test_pattern_replacement() {
        let engine = TokenizationEngine::new().unwrap();
        let args = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer {{ TOKEN }}".to_string(),
        ];
        let mut values = HashMap::new();
        values.insert("TOKEN".to_string(), "secret123".to_string());

        let result = engine.replace_patterns(&args, &values).unwrap();
        assert_eq!(result[2], "Authorization: Bearer secret123");
    }

    #[test]
    fn test_missing_key_error() {
        let engine = TokenizationEngine::new().unwrap();
        let args = vec!["echo".to_string(), "{{ MISSING_KEY }}".to_string()];
        let values = HashMap::new();

        let result = engine.replace_patterns(&args, &values);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Key 'MISSING_KEY' not found")
        );
    }

    #[test]
    fn test_secure_string_zeroization() {
        let secret = "sensitive_data".to_string();
        let secure = SecureString::new(secret);
        assert_eq!(secure.as_str(), "sensitive_data");
        // SecureString will zeroize on drop
    }
}
