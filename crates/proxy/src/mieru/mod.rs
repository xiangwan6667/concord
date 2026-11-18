mod cipher;
mod congestion;
mod frame;
mod meta;
mod packet;
mod padding;
mod pattern;
mod session;
mod stream;
mod udp;
mod underlay;

#[cfg(test)]
mod packet_tests;
#[cfg(test)]
mod tests;

use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession, Tasks,
};
use concord_config::proxy::{MieruOpts, ProxyDef};
use rand::Rng;

use self::packet::{Carrier, PacketUnderlay};
use self::pattern::Pattern;
use self::stream::MieruStream;
use self::underlay::{Underlay, Wire};
use crate::addr_codec::SOCKS;
use crate::ctx::{BuildCtx, BuildError, Clock};
use crate::dgram::StreamSession;
use crate::node::{Egress, info_for, resolve_server};
use crate::session_slot::{Resets, Ticket, overtaken};
use crate::util::lock;

const CONNECT: u8 = 1;
const UDP_ASSOCIATE: u8 = 3;
const MTU: usize = 1400;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handshake {
    Standard,
    NoWait,
}

struct Pool {
    underlays: Mutex<Underlays>,
}

#[derive(Default)]
struct Underlays {
    resets: Resets,
    live: Vec<Arc<dyn Wire>>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.close_all();
    }
}

impl Pool {
    fn pick(&self, factor: usize) -> Option<Arc<dyn Wire>> {
        let mut underlays = lock(&self.underlays);
        underlays.live.retain(|underlay| !underlay.is_closed());
        let active: Vec<_> = underlays
            .live
            .iter()
            .filter(|underlay| underlay.usable())
            .cloned()
            .collect();
        if factor == 0 {
            return None;
        }
        let reuse = active.len() * factor;
        let pick = rand::rng().random_range(0..=reuse);
        if pick < reuse {
            return active.get(pick / factor).cloned();
        }
        None
    }

    fn ticket(&self) -> Ticket {
        lock(&self.underlays).resets.ticket()
    }

    /// Takes in an underlay dialled under `ticket`. On false a reset ran since, and the caller
    /// closes the underlay.
    fn add(&self, underlay: Arc<dyn Wire>, ticket: Ticket) -> bool {
        let mut underlays = lock(&self.underlays);
        if !underlays.resets.none_since(ticket) {
            return false;
        }
        underlays.live.push(underlay);
        true
    }

    fn close_all(&self) {
        let closing = {
            let mut underlays = lock(&self.underlays);
            underlays.resets.bump();
            std::mem::take(&mut underlays.live)
        };
        for underlay in closing {
            underlay.close();
        }
    }
}

struct Mieru {
    info: OutboundInfo,
    egress: Egress,
    server: String,
    ports: (u16, u16),
    datagram: bool,
    user: String,
    hashed: [u8; 32],
    factor: usize,
    handshake: Handshake,
    pattern: Arc<Pattern>,
    clock: Clock,
    pool: Pool,
    tasks: Tasks,
}

fn request(command: u8, dst: &Address) -> io::Result<Vec<u8>> {
    let mut out = vec![5, command, 0];
    SOCKS.write(dst, &mut out)?;
    Ok(out)
}

impl Mieru {
    async fn dial(&self, cx: &DialCx<'_>) -> io::Result<Arc<dyn Wire>> {
        let (low, high) = self.ports;
        let port = if low == high {
            low
        } else {
            rand::rng().random_range(low..=high)
        };
        let ticket = self.pool.ticket();
        let secs = (self.clock)()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0));
        let key = cipher::derive_key(&self.hashed, secs);
        let target = Address::new(&self.server, port);
        let underlay: Arc<dyn Wire> = if self.datagram {
            let server = resolve_server(cx, &target, self.egress.version()).await?;
            let carrier = match self.egress.via() {
                Some(via) => {
                    let inner = cx.enter(self.egress.name())?;
                    let hint = Address::from(server);
                    Carrier::Session(cx.env.nodes.associate_via(via, &inner, &hint).await?)
                }
                None => Carrier::Socket(
                    cx.env
                        .sockets
                        .bind_udp(server.ip(), &self.egress.sock_opts(cx.env))?,
                ),
            };
            PacketUnderlay::start(
                carrier,
                server,
                &key,
                &self.user,
                self.pattern.clone(),
                MTU,
                self.factor,
                &self.tasks,
            )
        } else {
            let conn = self.egress.dial(cx, &target).await?;
            Underlay::start(
                conn,
                &key,
                &self.user,
                self.pattern.clone(),
                self.factor,
                &self.tasks,
            )
        };
        if !self.pool.add(underlay.clone(), ticket) {
            underlay.close();
            return Err(overtaken());
        }
        Ok(underlay)
    }

    fn open_on(
        underlay: &Arc<dyn Wire>,
    ) -> io::Result<(u32, tokio::sync::mpsc::Receiver<underlay::Event>)> {
        let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
        for _ in 0..8 {
            let id = rand::rng().random_range(1..=u32::MAX);
            match underlay.open_session(id) {
                Ok(events) => return Ok((id, events)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = err,
                Err(err) => return Err(err),
            }
        }
        Err(last)
    }

    async fn session(
        &self,
        cx: &DialCx<'_>,
        command: u8,
        dst: &Address,
    ) -> io::Result<MieruStream> {
        let head = request(command, dst)?;
        let fragment = match self.pattern.low_entropy {
            Some(low) => padding::max_fragment(low.mode),
            None => meta::MAX_PDU,
        };
        let reused = self.pool.pick(self.factor);
        let attached = match reused {
            Some(underlay) => Self::open_on(&underlay).map(|(id, events)| (underlay, id, events)),
            None => Err(io::ErrorKind::NotFound.into()),
        };
        let (underlay, id, events) = match attached {
            Ok(found) => found,
            Err(_) => {
                let fresh = self.dial(cx).await?;
                let (id, events) = Self::open_on(&fresh)?;
                (fresh, id, events)
            }
        };
        let mut stream = MieruStream::new(id, underlay, events, fragment);
        match self.handshake {
            Handshake::Standard => stream.handshake(head).await?,
            Handshake::NoWait => stream.set_head(head),
        }
        Ok(stream)
    }
}

#[async_trait]
impl Outbound for Mieru {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(self.session(cx, CONNECT, dst).await?))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let stream = self.session(cx, UDP_ASSOCIATE, hint).await?;
        Ok(Arc::new(StreamSession::new(
            Box::new(stream),
            udp::Frames,
            udp::Frames,
            hint.clone(),
            &self.tasks,
        )))
    }

    fn reset_sessions(&self) {
        self.pool.close_all();
    }
}

/// mieru's `MaxUserNameLen`, which also bounds the password.
const MAX_CREDENTIAL: usize = 64;

fn port_range(text: &str) -> Result<(u16, u16), BuildError> {
    let invalid = || BuildError::invalid("mieru: invalid port-range format");
    let (begin, end) = text.split_once('-').ok_or_else(invalid)?;
    let digits = |part: &str| -> Result<i64, BuildError> {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        part.parse().map_err(|_| invalid())
    };
    let (begin, end) = (digits(begin)?, digits(end)?);
    let bounded = |port: i64, which: &str| {
        u16::try_from(port)
            .ok()
            .filter(|port| *port >= 1)
            .ok_or_else(|| {
                BuildError::invalid(format!("mieru: {which} port must be between 1 and 65535"))
            })
    };
    let begin = bounded(begin, "begin")?;
    let end = bounded(end, "end")?;
    if begin > end {
        return Err(BuildError::invalid(
            "mieru: begin port must be less than or equal to end port",
        ));
    }
    Ok((begin, end))
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &MieruOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(Arc::new(construct(def, opts, ctx)?))
}

fn construct(def: &ProxyDef, opts: &MieruOpts, ctx: &BuildCtx) -> Result<Mieru, BuildError> {
    let invalid = |message: &str| BuildError::invalid(format!("mieru: {message}"));
    if def.name.is_empty() {
        return Err(invalid("name is empty"));
    }
    if opts.server.is_empty() {
        return Err(invalid("server is empty"));
    }
    let ports = match (opts.port, opts.port_range.is_empty()) {
        (0, true) => return Err(invalid("either port or port-range must be set")),
        (_, false) if opts.port != 0 => {
            return Err(invalid(
                "port and port-range cannot be set at the same time",
            ));
        }
        (0, false) => port_range(&opts.port_range)?,
        (port, _) => (port, port),
    };
    if opts.transport != "TCP" && opts.transport != "UDP" {
        return Err(invalid("transport must be TCP or UDP"));
    }
    if opts.username.is_empty() {
        return Err(invalid("username is empty"));
    }
    if opts.password.is_empty() {
        return Err(invalid("password is empty"));
    }
    if opts.username.len() > MAX_CREDENTIAL {
        return Err(invalid("user name exceeds 64 bytes"));
    }
    if opts.password.len() > MAX_CREDENTIAL {
        return Err(invalid("user password exceeds 64 bytes"));
    }
    let factor = match opts.multiplexing.as_str() {
        "" | "MULTIPLEXING_DEFAULT" | "MULTIPLEXING_LOW" => 1,
        "MULTIPLEXING_OFF" => 0,
        "MULTIPLEXING_MIDDLE" => 2,
        "MULTIPLEXING_HIGH" => 3,
        other => return Err(invalid(&format!("invalid multiplexing level: {other}"))),
    };
    let handshake = match opts.handshake_mode.as_str() {
        "" | "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => Handshake::Standard,
        "HANDSHAKE_NO_WAIT" => Handshake::NoWait,
        other => return Err(invalid(&format!("invalid handshake mode: {other}"))),
    };
    let pattern = Pattern::parse(&opts.traffic_pattern).map_err(|err| {
        BuildError::invalid(format!(
            "mieru: failed to decode traffic pattern {:?}: {err}",
            opts.traffic_pattern
        ))
    })?;
    let addr_port = ports.0;
    Ok(Mieru {
        info: info_for(
            def,
            OutboundKind::Mieru,
            &opts.server,
            addr_port,
            def.common.udp,
        ),
        egress: Egress::new(&def.name, &def.common),
        server: opts.server.clone(),
        ports,
        datagram: opts.transport == "UDP",
        user: opts.username.clone(),
        hashed: cipher::hash_password(&opts.password, &opts.username),
        factor,
        handshake,
        pattern: Arc::new(pattern),
        clock: ctx.clock.clone(),
        pool: Pool {
            underlays: Mutex::new(Underlays::default()),
        },
        tasks: ctx.tasks.clone(),
    })
}
