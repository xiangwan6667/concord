# Behaviour checklist

An embedding host relies on behaviour that no method signature shows. This file lists 45 such items and the test that holds each one. The items were drawn up when Concord was checked against the Go core's control protocol, so their numbering and the method and field names in the Behaviour column are that protocol's; `schema/api.json` is Concord's protocol, and the last section maps each item to its test on it. Tests are named as `crate::path::name`; a name without a crate prefix lives in the same file as the row above it.

Status values:

- **verified**: a test asserts the behaviour as written.
- **partial**: a test asserts part of it; the note says what is left.
- **not verified**: no test asserts it. The note says how it was checked, if at all.

These are host tests. Android was exercised by hand in an embedding app on an emulator; nothing here has run on Windows.

## Configuration loading

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 1 | A rejected `config.setup` applies the built-in empty config and answers `config_rejected` | partial | `concord-api::behaviour::a_rejected_profile_is_rejected_with_a_fallback_and_the_core_keeps_running` (`rejected` with `fellBack`); `concord-engine::e2e::a_rejected_config_falls_back_to_direct_and_says_so`. A failing empty config answering `internal` is not tested |
| 2 | `options` apply before the profile is read | partial | `concord-api::behaviour::options_take_effect_before_the_profile_is_read` asserts the test URL, not the timeout |
| 3 | `config.setup` opens no port; `listener.start` does | verified | `concord-api::behaviour::engine_start_opens_the_port_and_an_apply_alone_does_not` |
| 4 | Providers load asynchronously and each reports `loaded` | verified | Now `resourceUpdate`, every step of whose first load waits for the apply to finish: `concord-api::behaviour::each_provider_reports_loaded_after_the_apply_has_answered`, `an_apply_does_not_wait_for_a_provider_download`; `concord-engine::e2e::the_first_loads_report_their_outcome_only_once_the_apply_lets_them`. Every later fetch reports too: `concord-group::providers::an_http_provider_reports_every_fetch_whatever_started_it`, `concord-engine::geo_update` |
| 5 | `config.yaml` is written atomically and loads on its own | partial | `concord-api::behaviour::an_apply_with_a_profile_and_a_json_overlay_leaves_a_config_that_loads_alone`. The file exists and loads; that it goes through a temporary file and a rename is not asserted |
| 6 | Overlay merge, inlined anchors, light `profile.base` | partial | `concord-config::merge::merging_puts_added_rules_first_and_the_overlay_over_the_rest`, `base_leaves_the_bulk_sections_out_and_counts_them`, `the_merged_text_loads_without_the_profile`. An anchor defined in a replaced section is not tested |
| 7 | A response over 1 MiB goes to `<home>/responses`, spelled as Dart compares it; a failed write falls back to inline; errors are never spilled | verified | Replaced by the caller's `output` file (`schema/api.json`): `concord-api::behaviour::a_large_result_goes_to_the_file_the_caller_names_and_only_inside_the_home`, `a_missing_file_is_not_found_and_not_a_bare_message`. There is no `<home>/responses` and no implicit spill |
| 8 | `core.init` clears `<home>/responses` | verified | Gone with the spill directory: nothing is written under `<home>/responses`, so there is nothing to clear |

## Selection and route state

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 9 | `proxy.select` is answered while a setup is still applying | verified | `concord-api::behaviour::a_selection_is_answered_while_an_apply_is_still_applying` |
| 10 | `selected-map` keeps a pick for a gone member; the pick itself is refused | verified | `concord-api::behaviour::a_selection_for_a_gone_member_is_kept_in_the_map_and_refused_as_a_pick`; `concord-group::groups::a_stored_pick_of_a_removed_member_falls_back_to_the_first`, `a_selector_pinned_on_a_node_the_config_dropped_is_rejected` |
| 11 | Reset and Moved bump the epoch and version as listed; a reset follows the work it reports (an apply's listeners, a start, a stop, a network reset) and carries `running`, the listeners' state as of that reset | partial | `concord-engine::route_stamp` (five tests), `concord-engine::route::the_listeners_state_travels_with_the_epoch`, `concord-engine::geo_update`, `concord-engine::e2e::a_live_update_changes_the_mode_and_the_route_stamp`, `concord-group::groups::select_moves_the_route_once_per_change`. Not asserted: a TUN start resetting the stamp, an apply resetting it only after its listeners, a url-test or fallback change moving it, a successful geo update moving it. A provider swap that also changes a pick advances `version` by 2 where Go advances it by 1; Dart only needs it to advance |
| 12 | Probe results carry the stamp read before they start; `exitName` is deterministic and changes with the node | verified | `concord-engine::probe::tests::outbound_ip::the_answer_carries_the_stamp_and_the_exit_it_reached`, `a_lookup_from_an_older_epoch_is_cancelled`, `services::answers_carry_the_route_stamp`; `concord-group::providers::an_update_swaps_the_members_the_pick_and_the_exit`; `concord-group::groups::a_load_balancer_is_its_own_exit_identity_and_stops_udp_consulting` |
| 13 | `routeChanged` events keep stamp order | verified | `concord-engine::route::concurrent_advances_are_published_in_stamp_order` |

## Shape of `proxy.list`

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 14 | `all` holds group names in config order, `GLOBAL` first | verified | `concord-group::views::the_group_list_puts_global_first_and_keeps_config_order` |
| 15 | `proxies` holds every routable name; a provider node wins a shared name | verified | `concord-group::views::proxies_list_builtins_nodes_provider_nodes_and_groups_without_ghosts`, `a_provider_node_wins_a_name_it_shares_with_a_config_node` |
| 16 | Node views are `{name, type, provider-name?}` with the literal type names Dart reads | verified | `concord-api::behaviour::proxy_groups_have_the_order_the_shape_and_the_literal_names_dart_reads`; `concord-group::groups::the_policy_names_match_the_wire_types` |
| 17 | Group types, `LoadBalance` without `now`, `GLOBAL` hidden | verified | `concord-group::views::a_load_balancer_has_no_now_and_the_hidden_flag_follows_the_config`, `a_selector_view_lists_members_and_hides_the_default_test_url`, `url_test_and_fallback_views_carry_the_url_the_fixed_pick_and_the_icon` |

## Connections and event JSON

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 18 | Tracker keys, exit first in `chains` | partial | The tracker is `ConnectionInfo` (sparse, integer ids). `concord-api::behaviour::connections_arrive_as_a_snapshot_then_opens_counters_and_closes`; the field set is pinned by `schema/api.json` and Dart's `test/core/api/contract_test.dart`. Exit-first `chains` is held by the conversion, not by a test of its own |
| 19 | `metadata` keys, string ports, empty unset addresses | partial | Ports are integers and unset addresses are absent; the schema and the Dart contract test pin the field names and types |
| 20 | `dnsMode` is one of four names or null | partial | `dnsMode` is an optional string in `ConnectionInfo`; the schema pins the field, the four names are not asserted |
| 21 | `log`, `subscription-info` and `update-at` keys | verified | `concord-api::behaviour::a_provider_has_the_subscription_numbers_and_an_update_time_in_milliseconds`; log entries are `{level, time, text}` in `schema/api.json` |
| 22 | A `delay` event for every URL test, naming the URL used | partial | `concord-api::behaviour::a_delay_test_names_its_url_and_a_watcher_that_asked_sees_it`; `concord-group::delays::a_delay_is_the_virtual_time_the_node_took_and_goes_out_as_an_event`. Health-check events are not asserted separately from manual tests |
| 23 | `requestTraffic` is cumulative, only changed requests, five more cycles after close | verified | `concord-tunnel::table::traffic_is_reported_once_per_change_and_stops_when_idle`, `a_closed_connection_gives_up_after_its_retries_when_the_queue_stays_full` |

## Event queue

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 24 | Three queues, 256 deep each | verified | Replaced by per-stream policies and credit (`schema/api.json`): `concord-rpc` tests `without_credit_the_stream_is_not_polled_at_all`, `latest_keeps_only_the_newest_value_for_a_slow_consumer`, `drop_oldest_reports_how_many_events_a_slow_consumer_lost`, `resync_overflow_stops_the_stream_with_a_resync_and_never_drops_silently` |
| 25 | Batches flush at 32 events or 16 ms; drain order state, priority, bulk with a bulk turn after 8 priority events | verified | Replaced by `maxBatchMs` and `maxBatchBytes` per subscription: `concord-rpc::a_batch_collects_events_for_its_window_and_stops_at_its_size`. There is no cross-class drain order any more |
| 26 | Eviction per class: oldest for priority, log and request; newest for state, dns and requestTraffic | verified | Replaced by the policy per stream: `latest`, `drop_oldest`, `resync` (item 24). `connection.watch` resyncs past 8192 pending changes: `concord-api::bus::too_many_pending_changes_end_in_a_resync_and_nothing_is_dropped_silently` |
| 27 | Events are encoded at flush time | verified | Events are encoded when a batch is cut (`concord-rpc::dispatch::encode_events`), covered by the batch tests in item 25 |
| 28 | A failed delivery is reported on stderr only, never through the log system | not verified | `concord-rpc::server::report_delivery` writes to stderr and nowhere else, by reading the code; the test that held this item went with the old `ipc.rs` |

## Desktop process

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 29 | One argument; digits mean a TCP port; no argument prints an error and exits 1 | verified | `bins/desktop/tests/process.rs` (no-argument and TCP port tests) |
| 30 | The core dials the host; 64 MiB frame limit | verified | `concord-ipc::frame` tests (little-endian length, oversize header skipped, the stream stays in step); the TCP dial test in `bins/desktop/tests/process.rs`. An oversize message is now answered `payload_too_large` (`schema/api.json`) |
| 31 | Write deadline of 10 s; drop the frame if nothing was written, finish a started one, disconnect on a hard error | verified | `concord-ipc::frame` stall and hard-error tests |
| 32 | Exit within 3 s of a disconnect or SIGINT or SIGTERM | partial | `process.rs` disconnect and SIGTERM tests, unix only. SIGINT is handled in `ipc.rs` but not separately tested. Removing Linux policy routes on exit and cleaning leftovers at start are not tested here |
| 33 | The process stays the one that was started; stderr stays open | partial | `process.rs` checks the pid and an open stderr on unix. The Windows Helper comparing PIDs and treating stderr EOF as exit has not been run |

## Routing and dialing

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 34 | `Pass` in the exit chain continues to the next rule; UDP without UDP support continues | verified | `concord-engine::e2e::a_pass_in_a_group_moves_on_to_the_next_rule`, `udp_skips_a_rule_whose_outbound_has_no_udp`; `concord-group::groups::pass_and_pass_rule_resolve_to_their_own_variants_through_a_group` |
| 35 | `find-process-mode` `always` looks up every connection; `strict` (the default) only when a rule asks; `off` never does | verified | `concord-engine::e2e::find_process::each_find_process_mode_looks_up_the_owner_when_it_says`, switching the mode live between flows; `concord-rules::program_tests::processes_are_looked_up_on_demand` covers the rule side |
| 36 | A rejected config runs the empty config; no match goes DIRECT | verified | `concord-engine::e2e::a_rejected_config_falls_back_to_direct_and_says_so` |
| 37 | An empty group uses `empty-fallback` | partial | `concord-group::groups::an_emptied_group_falls_back_to_compatible`, `concord-group::views::an_emptied_group_lists_its_fallback_and_one_of_ghosts_lists_nothing`. The first-download-direct case before a provider loads is covered by `concord-engine::e2e::providers_load_over_the_tunnel_and_update_on_request` only indirectly |
| 38 | Desktop DIRECT refuses a loop into the core, without retrying | partial | `concord-engine::e2e::direct_refuses_a_loop_back_into_the_core`. That the error is not retried, and that Android does not apply the check, are not asserted |
| 39 | Android fd pressure at 3/4 of the limit, recheck, recovery | partial | `concord-platform::limits::pressure_follows_the_limit_and_recovers`, `the_limit_can_be_read_and_raised`. The dial refusal and the log lines are not asserted here |
| 40 | `listener.start` and `listener.stop` reset the resolver connections | not verified | Read in the code (`reset_resolver_connections` is called from both); no test |

## Selection and trust

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 41 | `proxy.select` reaches url-test and fallback; an empty name clears; a stranger returns a message | verified | `concord-group::groups::select_reports_the_go_messages`, `clearing_a_selector_stores_an_empty_pick_and_lands_on_the_first_member`, `a_url_test_group_skips_dead_members_and_honors_a_pin` |
| 42 | A dead pinned fallback member is dropped; selecting a dead one probes first | verified | `concord-group::groups::a_pinned_fallback_member_is_dropped_once_it_dies`, `selecting_a_dead_fallback_member_probes_it_first` |
| 43 | `config.setup` replaces the whole selection store | verified | `concord-group::selection::replace_all_drops_the_previous_picks_and_checks_nothing`; `concord-engine::e2e::the_selected_map_is_honoured_when_a_config_applies` |
| 44 | Global `skip-cert-verify` reaches only the default HTTP client | not verified | The tunnel fetcher reads the option and the URL-test client sets false, by code reading only. The Go `certificate_test` has no port |
| 45 | `proxy.definition` answers inline, age-encrypted and share-link providers | partial | `concord-group::providers::definition_returns_the_mapping_of_a_provider_node_only` covers provider nodes. The three source kinds are not tested one by one |

## Dashboards and state sync

| # | Behaviour | Status | Tests and notes |
|---|---|---|---|
| 46 | A pick or a general setting changed from either side is one `stateChanged` with its origin, numbered in the order it took effect; a call that changes nothing publishes nothing and answers the last `seq` | verified | `concord-engine::state_changes::changes_carry_their_origin_and_are_numbered_in_the_order_they_took_effect` |
| 47 | A `proxy.select` of a dead fallback member publishes the pick, then probes it holding back no change from the other side; a pick the core drops for a dead node is one `origin: core` change; a patch reports every setting `config.general` returns | verified | `concord-engine::state_changes::{a_select_publishes_its_pick_before_it_probes_and_holds_back_no_other_change, a_pick_the_core_drops_for_a_dead_node_is_reported_as_its_own_change, every_setting_the_general_view_reports_is_part_of_a_change}` |
| 48 | A dashboard's pick and patch reach the host as `origin: controller`; a patch naming a setting Concord cannot change applies nothing; `PUT /configs` and `tun` are the host's | verified | `concord-controller::routes::proxies_list_groups_and_nodes_and_a_pick_reaches_the_host_as_a_change`, `a_patch_changes_what_concord_changes_live_and_refuses_the_rest_whole` |
| 49 | The controller opens only where `config.patch` (embedded) or the profile (`concord run`) says, moves with it and closes on an empty address | verified | `concord-controller::routes::a_new_address_moves_the_controller_and_an_empty_one_closes_it`, `a_core_on_its_own_takes_the_controller_from_its_profile_and_reloads_a_payload` |
| 50 | The controller answers a browser only from the origins `externalControllerCors` (embedded) or `external-controller-cors` (`concord run`) allows, mihomo's `*` by default | verified | `concord-controller::routes::a_host_that_lists_origins_lets_only_those_call_from_a_browser`, `a_core_on_its_own_takes_the_allowed_origins_from_its_profile`, `an_embedded_core_ignores_the_profiles_allowed_origins_with_a_warning`, `http::tests::only_the_listed_origins_are_allowed` |

## Go tests ported

Each test file of the Go core's control layer, and where its semantics live in Rust.

| Go test file | Status | Rust counterpart |
|---|---|---|
| `certificate_test` | not ported | The behaviour is item 44 |
| `common_test` | partial | Pieces live in `concord-common` and `concord-platform` tests; not mapped one by one |
| `config_test` | partial | `concord-config` unit tests, the golden corpus (`crates/config/tests/golden.rs`) and `concord-engine::e2e`. Not ported: the geo auto-updater scheduling, `set_geo_resource_url`, authentication and TUN patch cases |
| `connection_test` | ported | `concord-tunnel::table::only_proxy_totals_leave_out_direct_connections` and neighbours |
| `dns_query_test` | ported | `concord-engine::e2e::the_dns_listener_answers_from_hosts_over_udp_and_tcp`; `concord-dns` tests |
| `filter_test` | ported | `concord-config::filter` tests |
| `hub_test` | partial | Many cases map to `concord-group` tests and `concord-engine::e2e`; the rest were not audited |
| `ipc_test` | ported | `concord-ipc` tests and `bins/desktop/tests/process.rs` |
| `message_test` | ported | Replaced by the stream policies and batching of `concord-rpc` (items 24 to 27) |
| `mitm_test` | ported | The `mitm_*` cases of `concord-engine::e2e`, `concord-mitm::config` and `concord-mitm::quickjs` tests |
| `outbound_ip_test` | ported | `concord-engine::probe::tests::outbound_ip` |
| `ownership_test` | ported | `concord-platform::home` tests (`reclaim.rs`, `secure.rs`) |
| `probe_test` | ported | `concord-engine::probe::tests` (`routes.rs`, `fetch.rs`) |
| `profile_base_test` | ported | `concord-config::merge` tests |
| `request_traffic_test` | ported | `concord-tunnel::table` tests |
| `route_test` | ported | `concord-engine::route` tests and `concord-engine::route_stamp` |
| `rule_set_test` | ported | `concord-rules` rule set, mrs and geo tests |
| `service_check_test` | ported | `concord-engine::probe::tests::services` |
| `service_rules_test` | ported | `concord-engine::probe::tests::rules` |
| `share_link_test` | ported | `concord-config::share_link` tests |
| `short_id_test` | ported | `concord-config::yaml::short_ids_stay_text_in_every_position` |
| `spill_test` | not needed | The spill is gone (item 7) |
| mihomo MITM fork tests (2,916 lines) | ported | `concord-mitm` tests, one or more per Go test; the fake-ip case is `concord-engine::e2e::mitm_drops_quic_to_a_listed_host_by_name_or_fake_ip`, because the tunnel resolves fake IPs before the engine sees a flow |

Go tests tied to Go internals (controller credentials, Go panics, gomobile) have no Rust counterpart.

## The typed control stack (`concord-api`, `concord-rpc`, `concord-ipc`)

The new stack carries the same service behaviour under new names (`config.apply` for `config.setup`, `engine.start` for `listener.start`, `proxy.groups` for `proxy.list`, `events.watch` for the event queue). Tests live in `crates/api/tests/behaviour.rs` unless a crate is named.

| # | New test |
|---|---|
| 1 | `a_rejected_profile_is_rejected_with_a_fallback_and_the_core_keeps_running` (answers `rejected` with `fellBack: true`; the empty-config failure path stays untested) |
| 2 | `options_take_effect_before_the_profile_is_read` |
| 3 | `engine_start_opens_the_port_and_an_apply_alone_does_not`; `the_engine_state_stream_reports_each_step_the_core_takes` |
| 4 | `each_provider_reports_loaded_after_the_apply_has_answered`, `an_apply_does_not_wait_for_a_provider_download` |
| 5, 6 | `an_apply_with_a_profile_and_a_json_overlay_leaves_a_config_that_loads_alone` (the overlay is sent as a JSON object and merges to the same file as the YAML string; `rules` is the key, no `rule`) |
| 9 | `a_selection_is_answered_while_an_apply_is_still_applying` |
| 10, 43 | `a_selection_for_a_gone_member_is_kept_in_the_map_and_refused_as_a_pick` |
| 13 | `a_pick_moves_the_route_and_the_watchers_hear_about_it_only_while_they_watch`, `a_patch_that_moves_the_mode_moves_the_route_stamp` |
| 14 to 17 | `proxy_groups_have_the_order_the_shape_and_the_literal_names_dart_reads` |
| 18 to 20 | `concord-api::convert::tests::a_connection_is_sparse_numeric_and_camel_case`; the connection shape is `ConnectionInfo`, not the Go tracker, so the Go key list does not apply |
| 21 | `a_provider_has_the_subscription_numbers_and_an_update_time_in_milliseconds` (the update time is Unix milliseconds, not RFC 3339) |
| 22 | `a_delay_test_names_its_url_and_a_watcher_that_asked_sees_it` |
| 28 | `concord-rpc::rpc::a_broken_write_ends_the_connection_and_is_not_reported_through_the_log_system` |
| 31 | `concord-ipc::frame::tests` (stall, hard error, oversized skip) and `concord-ipc::socket::a_slow_reader_does_not_lose_or_reorder_responses` |

Items that disappear, and why:

| # | Why it has no counterpart |
|---|---|
| 7, 8 | There is no implicit spill. A caller that wants a large result names `output.file` inside the home; `a_large_result_goes_to_the_file_the_caller_names_and_only_inside_the_home` covers it, and a result above the message limit is `payload_too_large`, never a spilled file. No `<home>/responses`, nothing to clear at `core.init` |
| 24 to 27 | The three queues, depth 256, the 32-event or 16 ms flush and the drain order are replaced by one policy per stream (`latest`, `drop_oldest`, `resync`), the consumer's credit, and `maxBatchMs`/`maxBatchBytes`. Covered by the slow-consumer tests in `concord-rpc::rpc` and `concord-api::stream::tests` |
| 29, 30, 32, 33 | Process behaviour is held by `bins/desktop/tests/process.rs`; the frame limit and dial are held by `concord-ipc` tests |
| 23 | Unchanged below the API; the new stream sends counters only for ids that changed (`connection_changes_coalesce_until_the_consumer_pulls`) |
