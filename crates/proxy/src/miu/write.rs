use super::{MiuStream, frame};
use crate::anytls::padding::Size;
use crate::miu::small_record;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;
use tokio::io::AsyncWrite;

impl MiuStream {
    pub(super) fn shape(&mut self) -> io::Result<()> {
        let Some(lane) = &mut self.inner else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        lane.packet = lane.packet.saturating_add(1);
        let padding = lane.shape.as_deref().unwrap_or(&self.pool.padding);
        let sizes = if lane.packet < padding.stop {
            padding.sizes(lane.packet)
        } else {
            Vec::new()
        };
        if sizes.is_empty() {
            let data = std::mem::take(&mut self.outgoing);
            return self.queue_unshaped(&data);
        }
        let data = std::mem::replace(&mut self.outgoing, std::mem::take(&mut lane.prefix));
        let mut position = 0;
        for item in sizes {
            let target = match item {
                Size::Check if position == data.len() => break,
                Size::Check => continue,
                Size::Bytes(size) if size > 3 && size < 8192 => size,
                Size::Bytes(_) => break,
            };
            let count = (data.len() - position).min(target);
            self.outgoing
                .extend_from_slice(data.get(position..position + count).unwrap_or_default());
            position += count;
            if count == 0 || target > count + 3 {
                let pad = if count == 0 {
                    target
                } else {
                    target - count - 3
                };
                self.append_padding(pad);
            }
            self.mark_record_end();
        }
        self.outgoing
            .extend_from_slice(data.get(position..).unwrap_or_default());
        self.mark_record_end();
        Ok(())
    }

    fn append_padding(&mut self, len: usize) {
        self.outgoing.push(0);
        self.outgoing.extend_from_slice(&(len as u16).to_be_bytes());
        self.outgoing.resize(self.outgoing.len() + len, 0);
    }

    fn mark_record_end(&mut self) {
        if !self.outgoing.is_empty() && self.record_ends.back() != Some(&self.outgoing.len()) {
            self.record_ends.push_back(self.outgoing.len());
        }
    }

    fn queue_unshaped(&mut self, frames: &[u8]) -> io::Result<()> {
        let Some(lane) = &mut self.inner else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let prefix = std::mem::take(&mut lane.prefix);
        let pad = if lane.io.is_tls() {
            small_record::padding_len(prefix.len() + frames.len())
        } else {
            None
        };
        self.outgoing.extend_from_slice(&prefix);
        if let Some(pad) = pad {
            self.append_padding(pad);
        }
        self.outgoing.extend_from_slice(frames);
        self.mark_record_end();
        Ok(())
    }

    pub(super) fn queue_control(&mut self, kind: u8) -> io::Result<()> {
        self.queue_unshaped(&[kind, 0, 0])
    }

    fn queue_data(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(16000) {
            if chunk.len() >= 280 {
                frame(&mut self.outgoing, 5, chunk)?;
                self.mark_record_end();
            } else {
                let mut framed = Vec::with_capacity(3 + chunk.len());
                frame(&mut framed, 5, chunk)?;
                self.queue_unshaped(&framed)?;
            }
        }
        Ok(())
    }

    fn queue_raw(&mut self, records: &[u8]) -> io::Result<()> {
        if records.len() < 4096 {
            return self.queue_data(records);
        }
        let mut announcement = Vec::new();
        let first = records
            .get(3..5)
            .and_then(|len| <[u8; 2]>::try_from(len).ok())
            .map_or(0, |len| 5 + usize::from(u16::from_be_bytes(len)));
        let raw = match records.split_at_checked(first) {
            Some((lead, tail)) if !lead.is_empty() && !tail.is_empty() && first + 10 <= 16384 => {
                frame(&mut announcement, 5, lead)?;
                tail
            }
            _ => records,
        };
        frame(&mut announcement, 6, &(raw.len() as u32).to_be_bytes())?;
        self.queue_unshaped(&announcement)?;
        self.raw_outgoing.extend_from_slice(raw);
        Ok(())
    }

    pub(super) fn queue_batch(&mut self, mut data: &[u8]) -> io::Result<()> {
        if self.up_scan.lost() {
            return self.queue_data(data);
        }
        let continuation = self.raw_hold.is_empty() && !self.up_scan.at_boundary();
        let (first, mut last) = self.up_scan.walk(data, &mut self.inner_tls13);
        if self.up_scan.lost() {
            self.flush_held_data()?;
            return self.queue_data(data);
        }
        if continuation {
            let Some(first) = first else {
                return self.queue_data(data);
            };
            let (framed, rest) = data.split_at(first);
            self.queue_data(framed)?;
            data = rest;
            last -= first;
        }
        if last != 0 {
            let (whole, rest) = data.split_at(last);
            if self.raw_hold.is_empty() {
                self.queue_raw(whole)?;
            } else {
                let mut held = std::mem::take(&mut self.raw_hold);
                held.extend_from_slice(whole);
                self.raw_wait = None;
                self.queue_raw(&held)?;
                held.clear();
                self.raw_hold = held;
            }
            data = rest;
        }
        if !data.is_empty() {
            if self.raw_hold.is_empty() {
                self.raw_wait = Some(Box::pin(tokio::time::sleep(Duration::from_millis(20))));
                self.wakers.read.wake();
            }
            self.raw_hold.extend_from_slice(data);
        }
        Ok(())
    }

    fn flush_held_data(&mut self) -> io::Result<()> {
        self.raw_wait = None;
        let mut held = std::mem::take(&mut self.raw_hold);
        self.queue_data(&held)?;
        held.clear();
        self.raw_hold = held;
        Ok(())
    }

    pub(super) fn poll_hold(&mut self, force: bool) -> Poll<io::Result<()>> {
        if self.raw_wait.is_none() && !self.raw_flushing {
            return Poll::Ready(Ok(()));
        }
        let waker = Waker::from(self.wakers.clone());
        let cx = &mut Context::from_waker(&waker);
        if let Some(wait) = &mut self.raw_wait {
            if !force {
                ready!(wait.as_mut().poll(cx));
            }
            ready!(self.drain(cx))?;
            self.flush_held_data()?;
            self.raw_flushing = true;
        }
        ready!(self.drain(cx))?;
        let lane = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let result = ready!(Pin::new(&mut lane.io).poll_flush(cx));
        self.raw_flushing = false;
        self.failed |= result.is_err();
        Poll::Ready(result)
    }
}
