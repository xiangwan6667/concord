use std::io::IoSlice;

use crate::seq::Seq;
use crate::stream::SharedState;
use crate::wire::{
    FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_SYN, IPV4_HEADER, IPV6_HEADER, L4Checksum, TCP_HEADER,
    TcpHeader, TcpOptions, emit_tcp, emit_tcp_head, options_len,
};

use super::{Egress, Phase, Sent, State, Tcb, mss_for};

const PAYLOAD_SLICES: usize = 8;
const MAX_HEAD: usize = IPV6_HEADER + TCP_HEADER + 40;
const MIN_SEND_BUFFER: usize = 64 * 1024;

impl Tcb {
    pub(super) fn update_send_cap(&mut self, state: &mut SharedState) {
        let want = (self.cc.cwnd as usize)
            .max(self.snd_wnd as usize)
            .saturating_mul(2)
            .clamp(
                MIN_SEND_BUFFER,
                self.config.send_buffer_max.max(MIN_SEND_BUFFER),
            );
        if want > state.send_cap {
            state.send_cap = want;
        }
    }

    fn segment_options(&mut self, now: u64, syn: bool, payload: usize) -> TcpOptions {
        let mut options = TcpOptions::default();
        if syn {
            options.mss = Some(mss_for(self.config.mtu, self.remote).min(65_535) as u16);
            let active = self.state == State::SynSent;
            if active || self.ws_ok {
                options.window_scale = Some(self.rcv_shift);
            }
            if active || self.sack_ok {
                options.sack_permitted = true;
            }
            if active || self.ts_ok {
                options.timestamp =
                    Some((self.ts_value(now), if active { 0 } else { self.ts_recent }));
            }
            return options;
        }
        if self.ts_ok {
            options.timestamp = Some((self.ts_value(now), self.ts_recent));
        }
        if self.sack_ok {
            let limit = if self.ts_ok { 3 } else { 4 };
            let mut blocks = std::mem::take(&mut self.sack_scratch);
            self.ooo.sack_blocks(&mut blocks, limit);
            if let Some(dsack) = self.dsack {
                blocks.insert(0, dsack);
                blocks.truncate(limit);
            }
            for (slot, (l, r)) in options.sack.iter_mut().zip(blocks.iter()) {
                *slot = (l.0, r.0);
            }
            options.sack_len = blocks.len().min(limit) as u8;
            self.sack_scratch = blocks;
            let fixed = self.ip_header() + TCP_HEADER + payload;
            while options.sack_len > 0 && fixed + options_len(&options) > self.config.mtu {
                options.sack_len -= 1;
            }
        }
        options
    }

    pub(super) fn emit(
        &mut self,
        egress: &mut dyn Egress,
        state: &SharedState,
        seq: Seq,
        payload: usize,
        flags: u8,
        now: u64,
    ) -> bool {
        self.emit_frame(egress, state, seq, payload, flags, now, 0)
    }

    #[allow(clippy::too_many_arguments, reason = "emit plus the segment size")]
    fn emit_frame(
        &mut self,
        egress: &mut dyn Egress,
        state: &SharedState,
        seq: Seq,
        payload: usize,
        flags: u8,
        now: u64,
        segment: u32,
    ) -> bool {
        let syn = flags & FLAG_SYN != 0;
        let per_packet = match segment as usize {
            0 => payload,
            segment => payload.min(segment),
        };
        let options = self.segment_options(now, syn, per_packet);
        let window = if syn {
            let window = self.rcv_cap.min(65_535);
            if self.state == State::SynReceived {
                self.rcv_adv = self.rcv_nxt + window;
            }
            window as u16
        } else {
            self.window_field(state)
        };
        let header = TcpHeader {
            src: self.local,
            dst: self.remote,
            seq: seq.0,
            ack: if flags & FLAG_ACK != 0 {
                self.rcv_nxt.0
            } else {
                0
            },
            flags,
            window,
        };
        let offset = seq.since(self.send_base) as usize;
        let checksum = egress.checksum();
        let segment = u16::try_from(segment)
            .ok()
            .filter(|&segment| segment > 0 && payload > usize::from(segment));
        let mut head = [0u8; MAX_HEAD];
        let mut slices = [IoSlice::new(&[]); PAYLOAD_SLICES];
        if payload > 0
            && checksum == L4Checksum::Pseudo
            && let Some(count) = state.send.slices_at(offset, payload, &mut slices)
            && let Some(head_len) = emit_tcp_head(&mut head, &header, &options, payload)
            && egress.send_in_place(
                segment.unwrap_or(0),
                head.get(..head_len).unwrap_or_default(),
                slices.get(..count).unwrap_or_default(),
            )
        {
            self.after_send(flags, now);
            return true;
        }
        let mut build = |buf: &mut [u8]| {
            emit_tcp(buf, &header, &options, payload, checksum, |body| {
                if payload == 0 {
                    return Some(());
                }
                state
                    .send
                    .copy_at(offset, body.get_mut(..payload)?)
                    .then_some(())
            })
        };
        let sent = match segment {
            Some(segment) => egress.send_segmented(segment, &mut build),
            None => egress.send(&mut build),
        };
        if sent {
            self.after_send(flags, now);
        }
        sent
    }

    fn after_send(&mut self, flags: u8, now: u64) {
        if flags & FLAG_ACK != 0 {
            self.ack_sent = self.rcv_nxt;
        }
        self.ack_pending = false;
        self.ack_now = false;
        self.ack_at = None;
        self.dsack = None;
        self.last_send = now;
    }

    fn ip_header(&self) -> usize {
        if self.remote.is_ipv4() {
            IPV4_HEADER
        } else {
            IPV6_HEADER
        }
    }

    pub(super) fn payload_room(&self, sack_blocks: usize) -> u32 {
        let ip = self.ip_header();
        let mut options = TcpOptions::default();
        if self.ts_ok {
            options.timestamp = Some((0, 0));
        }
        options.sack_len = sack_blocks as u8;
        let room = self
            .config
            .mtu
            .saturating_sub(ip + TCP_HEADER + options_len(&options)) as u32;
        room.min(self.mss).max(1)
    }

    /// Sends what the windows allow: SYN or SYN-ACK, lost segments, new data, FIN, and an ACK
    /// if one is owed. Returns false when the egress ran out of room.
    pub fn output(&mut self, now: u64, state: &mut SharedState, egress: &mut dyn Egress) -> bool {
        let done = self.output_inner(now, state, egress);
        self.sync_sent(state);
        done
    }

    pub(super) fn sync_sent(&self, state: &mut SharedState) {
        state.transmitted = if self.snd_nxt.gt(self.send_base) {
            (self.snd_nxt.since(self.send_base) as usize).min(state.send.len())
        } else {
            0
        };
    }

    fn output_inner(&mut self, now: u64, state: &mut SharedState, egress: &mut dyn Egress) -> bool {
        match self.state {
            State::Closed => return true,
            State::SynSent | State::SynReceived => {
                if self.syn_pending || self.ack_now {
                    let flags = if self.state == State::SynSent {
                        FLAG_SYN
                    } else {
                        FLAG_SYN | FLAG_ACK
                    };
                    if !self.emit(egress, state, self.iss, 0, flags, now) {
                        return false;
                    }
                    self.syn_pending = false;
                    self.snd_nxt = self.iss + 1;
                    self.rto_at.get_or_insert(now + self.rto());
                }
                return true;
            }
            _ => {}
        }
        let sack_room = if self.sack_ok && !self.ooo.is_empty() {
            if self.ts_ok { 3 } else { 4 }
        } else {
            0
        };
        let room = self.payload_room(sack_room);
        if !self.retransmit_lost(now, state, egress) {
            return false;
        }
        if !self.send_new(now, state, egress, room) {
            return false;
        }
        // A closed peer window accepts only SND.UNA; SND.NXT may still include in-flight data.
        let ack_seq = if self.snd_wnd == 0 {
            self.snd_una
        } else {
            self.snd_nxt
        };
        !self.ack_now || self.emit(egress, state, ack_seq, 0, FLAG_ACK, now)
    }

    fn retransmit_lost(&mut self, now: u64, state: &SharedState, egress: &mut dyn Egress) -> bool {
        if self.lost_bytes == 0 {
            return true;
        }
        let mut index = 0;
        while let Some(seg) = self.sent.get(index).copied() {
            index += 1;
            if !seg.lost || seg.retrans || seg.sacked {
                continue;
            }
            let len = seg.len();
            if self.inflight() + len > self.cc.cwnd && self.inflight() > 0 {
                self.cwnd_blocked = true;
                break;
            }
            let mut flags = FLAG_ACK;
            if seg.fin {
                flags |= FLAG_FIN;
            }
            if !self.emit(egress, state, seg.start, seg.payload(), flags, now) {
                return false;
            }
            if let Some(stored) = self.sent.get_mut(index - 1) {
                stored.retrans = true;
                stored.sent_at = now;
            }
            self.retrans_bytes += len;
            if self.phase == Phase::Recovery {
                self.prr_out += len;
            }
            self.rto_at.get_or_insert(now + self.rto());
        }
        true
    }

    fn send_new(
        &mut self,
        now: u64,
        state: &mut SharedState,
        egress: &mut dyn Egress,
        room: u32,
    ) -> bool {
        let frame = (egress.segment_limit() as u32 / room).max(1) * room;
        loop {
            let queued_end = self.send_base + state.send.len() as u32;
            let unsent = queued_end.since(self.snd_nxt);
            let can_fin = matches!(self.state, State::Established | State::CloseWait);
            let fin_ready = state.write_closed && self.fin_seq.is_none() && can_fin;
            if unsent == 0 && !fin_ready {
                break;
            }
            let window_end = self.snd_una + self.snd_wnd;
            let by_window = window_end.since(self.snd_nxt);
            let mut len = unsent.min(frame).min(by_window);
            if unsent > 0 && len == 0 {
                if self.snd_una == self.snd_nxt && self.persist_at.is_none() {
                    self.persist_at = Some(now + self.rto().max(200_000));
                }
                break;
            }
            let inflight = self.inflight();
            let open = self.cc.cwnd.saturating_sub(inflight);
            if open < len.max(1) {
                if inflight > 0 && (open < room || len <= room) {
                    self.cwnd_blocked = true;
                    break;
                }
                if len > room {
                    len = (open / room * room).max(room);
                }
            }
            let fin = fin_ready && len == unsent;
            let mut flags = FLAG_ACK;
            if len > 0 && len == unsent {
                flags |= FLAG_PSH;
            }
            if fin {
                flags |= FLAG_FIN;
            }
            if self.snd_una == self.snd_nxt && now.saturating_sub(self.last_send) > self.rto() {
                self.cc.on_idle();
            }
            if !self.emit_frame(egress, state, self.snd_nxt, len as usize, flags, now, room) {
                return false;
            }
            let start = self.snd_nxt;
            let end = start + len + u32::from(fin);
            let mut from = start;
            loop {
                let to = from + room.min(len - from.since(start));
                let last = to == start + len;
                self.sent.push_back(Sent {
                    start: from,
                    end: if last { end } else { to },
                    fin: fin && last,
                    sent_at: now,
                    sacked: false,
                    lost: false,
                    retrans: false,
                });
                if last {
                    break;
                }
                from = to;
            }
            self.snd_nxt = end;
            if self.phase == Phase::Recovery {
                self.prr_out += len + u32::from(fin);
            }
            self.max_inflight = self.max_inflight.max(self.inflight());
            if self.rto_at.is_none() {
                self.rto_at = Some(now + self.rto());
            }
            if fin {
                self.fin_seq = Some(start + len);
                self.state = match self.state {
                    State::CloseWait => State::LastAck,
                    _ => State::FinWait1,
                };
                break;
            }
        }
        if self.probe_at.is_none() {
            self.arm_probe(now);
        }
        true
    }
}
