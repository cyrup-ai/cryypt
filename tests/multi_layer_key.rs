use cryypt::key::{MultiLayerKey, entropy::EntropySource};

#[test]
fn test_multi_layer_key_creation() {
    let mut entropy = EntropySource::new().unwrap();
    let key = MultiLayerKey::new(&mut entropy).unwrap();
    
    assert_eq!(key.version(), 0);
    assert!(key.verify_integrity());
    assert_eq!(key.audit_log().len(), 0);
}

#[test]
fn test_key_rotation_increments_version() {
    let mut entropy = EntropySource::new().unwrap();
    let mut key = MultiLayerKey::new(&mut entropy).unwrap();

    assert_eq!(key.version(), 0);

    key.rotate_keys(&mut entropy).unwrap();
    assert_eq!(key.version(), 1);

    key.rotate_keys(&mut entropy).unwrap();
    assert_eq!(key.version(), 2);
}

#[test]
fn test_key_rotation_maintains_integrity() {
    let mut entropy = EntropySource::new().unwrap();
    let mut key = MultiLayerKey::new(&mut entropy).unwrap();

    assert!(key.verify_integrity());
    
    key.rotate_keys(&mut entropy).unwrap();
    assert!(key.verify_integrity());
}

#[test]
fn test_audit_logging() {
    let mut entropy = EntropySource::new().unwrap();
    let mut key = MultiLayerKey::new(&mut entropy).unwrap();

    key.rotate_keys(&mut entropy).unwrap();
    
    let log = key.audit_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].operation(), "rotate_keys");
    assert_eq!(log[0].key_version(), 1);
}

#[test]
fn test_key_layers_are_different() {
    let mut entropy = EntropySource::new().unwrap();
    let key = MultiLayerKey::new(&mut entropy).unwrap();
    
    // Ensure all three layers are different
    assert_ne!(key.layer1(), key.layer2());
    assert_ne!(key.layer2(), key.layer3());
    assert_ne!(key.layer1(), key.layer3());
}

#[test]
fn test_key_rotation_changes_all_layers() {
    let mut entropy = EntropySource::new().unwrap();
    let mut key = MultiLayerKey::new(&mut entropy).unwrap();
    
    let layer1_before = key.layer1().to_vec();
    let layer2_before = key.layer2().to_vec();
    let layer3_before = key.layer3().to_vec();
    
    key.rotate_keys(&mut entropy).unwrap();
    
    assert_ne!(key.layer1(), &layer1_before[..]);
    assert_ne!(key.layer2(), &layer2_before[..]);
    assert_ne!(key.layer3(), &layer3_before[..]);
}