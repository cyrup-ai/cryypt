use super::vault::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    pub(crate) async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }

        // Check for potentially dangerous regex patterns
        if pattern.len() > 100 || pattern.contains("(.*){") {
            return Err(VaultError::InvalidPattern(
                "Pattern too complex or potentially malicious".into(),
            ));
        }

        let data = self.data.lock().await;

        // If pattern is ".*", return all items
        if pattern == ".*" {
            let results: Vec<(String, VaultValue)> =
                data.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            return Ok(results);
        }

        // Otherwise, try to compile and use regex
        match regex::Regex::new(pattern) {
            Ok(re) => {
                let results: Vec<(String, VaultValue)> = data
                    .iter()
                    .filter(|(k, _)| re.is_match(k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(results)
            }
            Err(_) => {
                // Fallback to simple contains if regex is invalid
                let results: Vec<(String, VaultValue)> = data
                    .iter()
                    .filter(|(k, _)| k.contains(pattern))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(results)
            }
        }
    }

    pub(crate) async fn list_impl(&self) -> VaultResult<Vec<String>> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        Ok(self.data.lock().await.keys().cloned().collect())
    }
}