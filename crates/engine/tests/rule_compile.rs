use std::sync::Arc;

use concord_common::NullSink;
use concord_engine::{Engine, EngineConfig};
use concord_platform::NativePlatform;

#[tokio::test]
async fn local_rule_compilation_keeps_the_source_and_writes_a_readable_mrs() {
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NullSink),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    let home = tempfile::tempdir().unwrap();
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    let rules = home.path().join("providers/rules");
    std::fs::create_dir_all(&rules).unwrap();
    let source = b"payload:\n  - '+.example.com'\n";
    std::fs::write(rules.join("domains"), source).unwrap();
    let info = engine.compile_rule_set("domains", "").await.unwrap();
    assert_eq!((info.behavior, info.format), ("domain", "yaml"));
    assert_eq!(std::fs::read(rules.join("domains")).unwrap(), source);
    let info = engine.compile_rule_set("domains.mrs", "").await.unwrap();
    assert_eq!((info.behavior, info.format), ("domain", "mrs"));
    assert!(engine.compile_rule_set("missing", "").await.is_err());
    std::fs::write(rules.join("empty"), b"").unwrap();
    assert!(engine.compile_rule_set("empty", "").await.is_ok());
    engine.shutdown().await;
}
