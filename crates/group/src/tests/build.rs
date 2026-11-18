use super::*;

#[test]
fn group_config_errors_keep_the_source_line() {
    let source = concord_config::ConfigError::at("broken: filter: invalid regexp", 17);
    let error = crate::GroupError::from(source.clone());
    let preserved = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<concord_config::ConfigError>());
    assert_eq!(preserved, Some(&source));
}

#[tokio::test]
async fn invalid_group_filters_name_the_group_and_field() {
    for field in ["filter", "exclude-filter"] {
        for pattern in ["(", "valid`("] {
            let mut profile =
                profile("proxy-groups:\n  - {name: broken, type: select, proxies: [DIRECT]}\n");
            let group = profile
                .groups
                .iter_mut()
                .find(|g| g.name == "broken")
                .unwrap();
            match field {
                "filter" => group.filter = pattern.into(),
                _ => group.exclude_filter = pattern.into(),
            }
            let error = Rig::try_with(&profile, Arc::new(SelectionStore::new()), None)
                .err()
                .expect("invalid filter must fail to build");
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("broken: {field}: error parsing regexp:")),
                "{error}"
            );
            let source = std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<concord_config::ConfigError>())
                .expect("the config error must remain the source");
            assert_eq!(source.to_string(), error.to_string());
        }
    }
}
