use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver as Inbox, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use concord_api::sync::lock;
use concord_api::{Control, ControlOptions, EventBus};
use concord_engine::{Engine, EngineConfig};
use concord_platform::NativePlatform;
use concord_rpc::Server;
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use crate::dart::DartPort;
use crate::{
    Hub, Receiver, concord_close, concord_init_dart_api, concord_open, concord_open_callback,
    concord_send, hub, install,
};

const WAIT: Duration = Duration::from_secs(10);
const CLOSED_PORT: i64 = 13;

struct World {
    _runtime: Runtime,
    bus: Arc<EventBus>,
    #[cfg(unix)]
    home: tempfile::TempDir,
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let entered = runtime.enter();
        let bus = EventBus::new();
        let engine = Engine::new(EngineConfig {
            sink: bus.clone(),
            android: true,
            platform: Arc::new(NativePlatform::new()),
        });
        let control = Control::new(engine, bus.clone(), ControlOptions::default());
        let server = Arc::new(Server::new(control));
        drop(entered);
        assert!(install(Hub::new(runtime.handle().clone(), server)));
        World {
            _runtime: runtime,
            bus,
            #[cfg(unix)]
            home: tempfile::tempdir().unwrap(),
        }
    })
}

struct Host {
    inbox: Inbox<Vec<u8>>,
    alive: Arc<AtomicBool>,
    released: Arc<AtomicUsize>,
    session: u64,
}

struct Tap {
    sender: Sender<Vec<u8>>,
    alive: Arc<AtomicBool>,
    released: Arc<AtomicUsize>,
}

impl Receiver for Tap {
    fn deliver(&mut self, message: Vec<u8>) -> bool {
        if !self.alive.load(Ordering::SeqCst) {
            return false;
        }
        let _ = self.sender.send(message);
        true
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

fn open() -> Host {
    world();
    let (sender, inbox) = channel();
    let alive = Arc::new(AtomicBool::new(true));
    let released = Arc::new(AtomicUsize::new(0));
    let tap = Tap {
        sender,
        alive: alive.clone(),
        released: released.clone(),
    };
    let session = hub()
        .expect("the world installed a hub")
        .open(Box::new(tap));
    assert_ne!(session, 0);
    Host {
        inbox,
        alive,
        released,
        session,
    }
}

impl Host {
    fn send(&self, message: &Value) -> bool {
        let bytes = message.to_string().into_bytes();
        // SAFETY: the pointer and length describe `bytes`.
        unsafe { concord_send(self.session, bytes.as_ptr(), bytes.len()) != 0 }
    }

    fn next(&self) -> Value {
        serde_json::from_slice(&self.inbox.recv_timeout(WAIT).unwrap()).unwrap()
    }

    fn hello(&self) -> Value {
        assert!(self.send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {
            "protocol": {"min": 1, "max": 1},
            "client": {"name": "test", "version": "0"}}})
        ));
        self.next()
    }

    fn call(&self, id: u64, method: &str, params: Value) -> Value {
        assert!(
            self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        );
        self.next()
    }
}

fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the condition never held");
}

#[test]
fn a_session_answers_hello_and_ends_when_the_host_closes_it() {
    let host = open();
    let reply = host.hello();
    assert_eq!(reply["result"]["server"]["implementation"], "concord");
    assert_eq!(reply["result"]["protocol"], 1);

    concord_close(host.session);
    until(|| host.released.load(Ordering::SeqCst) == 1);
    assert!(!host.send(&json!({"id": 2, "method": "core.hello"})));
    concord_close(host.session);
}

#[derive(Default)]
struct Sink {
    replies: Mutex<Vec<Value>>,
    released: AtomicBool,
}

unsafe extern "C" fn sink_deliver(context: *mut c_void, data: *const u8, len: usize) -> bool {
    // SAFETY: `context` is the `Sink` the test registered and outlives the session; the core
    // passes `len` readable bytes at `data` for the duration of the call.
    let (sink, bytes) = unsafe {
        (
            &*context.cast::<Sink>(),
            std::slice::from_raw_parts(data, len),
        )
    };
    lock(&sink.replies).push(serde_json::from_slice(bytes).unwrap());
    true
}

unsafe extern "C" fn sink_release(context: *mut c_void) {
    // SAFETY: `context` is the `Sink` the test registered, which outlives the session.
    let sink = unsafe { &*context.cast::<Sink>() };
    sink.released.store(true, Ordering::SeqCst);
}

#[test]
fn a_callback_session_answers_through_deliver_and_is_released_once_closed() {
    world();
    let sink = Sink::default();
    let context = std::ptr::from_ref(&sink).cast_mut().cast();
    // SAFETY: `sink` outlives the session, which the test waits to see released.
    let session = unsafe { concord_open_callback(sink_deliver, context, Some(sink_release)) };
    assert_ne!(session, 0);
    let hello = json!({"jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {
        "protocol": {"min": 1, "max": 1}, "client": {"name": "test", "version": "0"}}})
    .to_string();
    // SAFETY: the pointer and length describe `hello`.
    let returned = unsafe { concord_send(session, hello.as_ptr(), hello.len()) };
    assert_ne!(returned, 0);
    until(|| !lock(&sink.replies).is_empty());

    concord_close(session);
    until(|| sink.released.load(Ordering::SeqCst));
    assert_eq!(lock(&sink.replies)[0]["result"]["protocol"], 1);
}

#[test]
fn a_message_for_no_session_is_refused() {
    world();
    // SAFETY: a null pointer with length 0 is never read.
    assert_eq!(unsafe { concord_send(u64::MAX, std::ptr::null(), 0) }, 0);
}

#[test]
fn a_receiver_that_reports_the_host_gone_ends_the_session_and_its_subscriptions() {
    let host = open();
    host.hello();
    let watch = host.call(2, "route.watch", json!({}));
    assert!(watch["result"]["sub"].is_u64(), "{watch}");
    let bus = world().bus.clone();
    assert_eq!(bus.topic_counts()[2], 1);

    host.alive.store(false, Ordering::SeqCst);
    assert!(host.send(&json!({"jsonrpc": "2.0", "id": 3, "method": "core.hello"})));
    until(|| bus.topic_counts() == [0; 5]);
    until(|| host.released.load(Ordering::SeqCst) == 1);
    until(|| !host.send(&json!({"id": 4})));
}

#[test]
fn each_session_has_its_own_subscriptions() {
    let first = open();
    let second = open();
    first.hello();
    second.hello();
    first.call(2, "log.watch", json!({}));
    second.call(2, "log.watch", json!({}));
    let bus = world().bus.clone();
    assert_eq!(bus.topic_counts()[0], 2);

    concord_close(first.session);
    until(|| bus.topic_counts()[0] == 1);
    concord_close(second.session);
    until(|| bus.topic_counts()[0] == 0);
}

#[cfg(unix)]
#[test]
fn an_adopted_descriptor_is_consumed_by_the_tun_start_that_names_it() {
    let host = open();
    host.hello();
    let home = world().home.path().to_str().unwrap().to_string();
    let init = host.call(2, "core.init", json!({"home": home, "sdkInt": 34}));
    assert!(init.get("error").is_none(), "{init}");

    let (reader, _writer) = std::io::pipe().unwrap();
    let handle = crate::concord_adopt_fd(std::os::fd::IntoRawFd::into_raw_fd(reader));
    assert_ne!(handle, 0);
    let source = json!({"source": {"kind": "inherited", "handle": handle}});

    host.call(3, "tun.start", source.clone());
    let again = host.call(4, "tun.start", source);
    assert_eq!(again["error"]["data"]["kind"], "not_found", "{again}");
    host.call(5, "tun.stop", json!({}));
    concord_close(host.session);
}

mod dart {
    use super::*;

    #[repr(C)]
    struct Table {
        major: c_int,
        minor: c_int,
        entries: *const Entry,
    }

    #[repr(C)]
    struct Entry {
        name: *const c_char,
        function: *const c_void,
    }

    #[repr(C)]
    struct Typed {
        kind: c_int,
        length: isize,
        values: *const u8,
    }

    #[repr(C)]
    struct External {
        kind: c_int,
        length: isize,
        data: *mut u8,
        peer: *mut c_void,
        finalizer: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    }

    #[repr(C)]
    union Payload {
        typed: std::mem::ManuallyDrop<Typed>,
        external: std::mem::ManuallyDrop<External>,
    }

    #[repr(C)]
    struct CObject {
        kind: c_int,
        payload: Payload,
    }

    static POSTED: Mutex<Vec<(i64, c_int, Vec<u8>)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn fake_post(port: i64, object: *mut CObject) -> bool {
        if port == CLOSED_PORT {
            return false;
        }
        // SAFETY: `object` is what `DartPort` built, laid out like `Dart_CObject`.
        let object = unsafe { &*object };
        let (bytes, finalizer) = match object.kind {
            // SAFETY: kind 7 is `kTypedData`.
            7 => unsafe {
                let typed = &object.payload.typed;
                (
                    std::slice::from_raw_parts(typed.values, typed.length as usize).to_vec(),
                    None,
                )
            },
            // SAFETY: kind 8 is `kExternalTypedData`.
            8 => unsafe {
                let external = &object.payload.external;
                (
                    std::slice::from_raw_parts(external.data, external.length as usize).to_vec(),
                    external.finalizer.map(|run| (run, external.peer)),
                )
            },
            other => panic!("unexpected object kind {other}"),
        };
        if let Some((run, peer)) = finalizer {
            // SAFETY: the real VM runs the finalizer when the received buffer is collected.
            unsafe { run(std::ptr::null_mut(), peer) };
        }
        lock(&POSTED).push((port, object.kind, bytes));
        true
    }

    fn initialize() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let entries = Box::leak(Box::new([
                Entry {
                    name: c"Dart_PostInteger".as_ptr(),
                    function: std::ptr::null(),
                },
                Entry {
                    name: c"Dart_PostCObject".as_ptr(),
                    function: fake_post as *const c_void,
                },
                Entry {
                    name: std::ptr::null(),
                    function: std::ptr::null(),
                },
            ]));
            let table = Box::leak(Box::new(Table {
                major: 2,
                minor: 6,
                entries: entries.as_ptr(),
            }));
            // SAFETY: the table has the layout of the VM's and ends with a null name.
            let returned = unsafe { concord_init_dart_api(std::ptr::from_ref(table).cast()) };
            assert_eq!(returned, 0);
        });
    }

    #[test]
    fn the_api_table_is_refused_when_it_is_not_the_expected_major() {
        let end = [Entry {
            name: std::ptr::null(),
            function: std::ptr::null(),
        }];
        let wrong = Table {
            major: 1,
            minor: 0,
            entries: end.as_ptr(),
        };
        // SAFETY: the table is well formed.
        let returned = unsafe { concord_init_dart_api(std::ptr::from_ref(&wrong).cast()) };
        assert_eq!(returned, -1);
        // SAFETY: a null table is refused before it is read.
        assert_eq!(unsafe { concord_init_dart_api(std::ptr::null()) }, -1);
    }

    #[test]
    fn small_messages_are_copied_and_large_ones_handed_over() {
        initialize();
        let mut port = DartPort(7);
        assert!(crate::hub::Receiver::deliver(&mut port, b"small".to_vec()));
        let large = vec![9u8; 40_000];
        assert!(crate::hub::Receiver::deliver(&mut port, large.clone()));

        let posted = lock(&POSTED);
        let small = posted
            .iter()
            .find(|(_, _, bytes)| bytes == b"small")
            .unwrap();
        assert_eq!((small.0, small.1), (7, 7));
        let big = posted
            .iter()
            .find(|(_, _, bytes)| bytes.len() == 40_000)
            .unwrap();
        assert_eq!((big.0, big.1, &big.2), (7, 8, &large));
    }

    #[test]
    fn a_closed_port_refuses_both_kinds_of_message() {
        initialize();
        let mut port = DartPort(CLOSED_PORT);
        assert!(!crate::hub::Receiver::deliver(&mut port, b"small".to_vec()));
        assert!(!crate::hub::Receiver::deliver(&mut port, vec![0; 40_000]));
    }

    #[test]
    fn a_session_on_a_port_that_closes_unsubscribes() {
        initialize();
        world();
        let live = concord_open(21);
        assert_ne!(live, 0);
        let bytes = br#"{"jsonrpc":"2.0","id":1,"method":"core.hello","params":{"protocol":{"min":1,"max":1},"client":{"name":"t","version":"0"}}}"#;
        // SAFETY: the pointer and length describe `bytes`.
        let returned = unsafe { concord_send(live, bytes.as_ptr(), bytes.len()) };
        assert_ne!(returned, 0);
        until(|| lock(&POSTED).iter().any(|(port, ..)| *port == 21));

        let doomed = concord_open(CLOSED_PORT);
        assert_ne!(doomed, 0);
        // SAFETY: as above.
        let returned = unsafe { concord_send(doomed, bytes.as_ptr(), bytes.len()) };
        assert_ne!(returned, 0);
        until(|| {
            // SAFETY: as above.
            unsafe { concord_send(doomed, bytes.as_ptr(), bytes.len()) == 0 }
        });
        concord_close(live);
        assert!(hub().is_some());
    }
}
