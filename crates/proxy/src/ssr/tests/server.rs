use std::io;
use std::sync::{Arc, Mutex};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf, BytesMut};
use concord_common::PacketBuf;
use concord_common::sync::lock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::addr_codec::SOCKS;
use crate::ssr::chain::{Chain, rc4_for, udp_rand_len};
use crate::ssr::cipher::{CipherLayer, SsrCipher, kdf};
use crate::ssr::protocol::{
    Aes, Auth, Hash, Kind, PacketProtocol, ProtocolFactory, ProtocolLayer, Sha1V4, hmac, hmac_md5,
};
use crate::ssr::stream::{BoxLayer, CodecStream, Layer};

type SharedIv = Arc<Mutex<Vec<u8>>>;

struct ServerCipher {
    inner: CipherLayer,
    iv_len: usize,
    peer_iv: SharedIv,
    seen: bool,
}

impl Layer for ServerCipher {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        self.inner.encode(out, data)
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        if !self.seen {
            if input.len() < self.iv_len {
                return Ok(());
            }
            *lock(&self.peer_iv) = input[..self.iv_len].to_vec();
            self.seen = true;
        }
        self.inner.decode(input, decoded, reply)
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        unreachable!("the test server is never split")
    }
}

struct ServerProtocol {
    factory: Arc<ProtocolFactory>,
    peer_iv: SharedIv,
    state: Option<ProtocolLayer>,
}

fn be16(bytes: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn rand_block(frame: &[u8], at: usize) -> usize {
    if frame[at] < 255 {
        usize::from(frame[at])
    } else {
        be16(&frame[at + 1..])
    }
}

impl ServerProtocol {
    fn open_header(&mut self, input: &mut BytesMut, decoded: &mut BytesMut) -> io::Result<()> {
        let iv = lock(&self.peer_iv).clone();
        let f = &self.factory;
        let user_key = f.user.key.clone();
        let key = f.base.key.clone();
        let mut mac_key = iv.clone();
        mac_key.extend_from_slice(&key);
        match f.kind {
            Kind::Origin => {
                self.state = Some(ProtocolLayer::Origin);
            }
            Kind::Sha1V4 => {
                if input.len() < 2 || input.len() < be16(input) {
                    return Ok(());
                }
                let total = be16(input);
                let frame = &input[..total];
                let block = rand_block(frame, 6);
                assert_eq!(
                    hmac(Hash::Sha1, &mac_key, &frame[..total - 10])[..10],
                    frame[total - 10..]
                );
                decoded.extend_from_slice(&frame[6 + block + 12..total - 10]);
                input.advance(total);
                self.state = Some(ProtocolLayer::Sha1V4(Sha1V4 {
                    key,
                    iv,
                    auth: Auth {
                        client_id: [0; 4],
                        connection_id: 0,
                    },
                    now: 0,
                    sent_header: true,
                    raw: false,
                }));
            }
            Kind::Aes(hash) => {
                if input.len() < 7 + 4 + 16 + 4 {
                    return Ok(());
                }
                let salt = if hash == Hash::Md5 {
                    "auth_aes128_md5"
                } else {
                    "auth_aes128_sha1"
                };
                let secret = format!("{}{salt}", STANDARD.encode(&user_key));
                let cipher = Aes128::new_from_slice(&kdf(secret.as_bytes(), 16)).unwrap();
                let mut block = aes::Block::clone_from_slice(&input[11..27]);
                cipher.decrypt_block(&mut block);
                let total = usize::from(u16::from_le_bytes([block[12], block[13]]));
                let rand_len = usize::from(u16::from_le_bytes([block[14], block[15]]));
                if input.len() < total {
                    return Ok(());
                }
                let frame = &input[..total];
                assert_eq!(
                    hmac(hash, &user_key, &frame[..total - 4])[..4],
                    frame[total - 4..]
                );
                decoded.extend_from_slice(&frame[7 + 4 + 16 + 4 + rand_len..total - 4]);
                input.advance(total);
                self.state = Some(ProtocolLayer::Aes(Box::new(Aes {
                    hash,
                    salt: if hash == Hash::Md5 {
                        "auth_aes128_md5"
                    } else {
                        "auth_aes128_sha1"
                    },
                    key,
                    overhead: f.base.overhead,
                    user_key,
                    user_id: f.user.id,
                    iv,
                    auth: Auth {
                        client_id: [0; 4],
                        connection_id: 0,
                    },
                    now: 0,
                    sent_header: true,
                    raw: false,
                    pack_id: 1,
                    recv_id: 1,
                })));
            }
            Kind::Chain(kind) => {
                if input.len() < 36 {
                    return Ok(());
                }
                let hash0 = hmac_md5(&mac_key, &input[..4]);
                assert_eq!(hash0[..8], input[4..12]);
                let server_hash = hmac_md5(&user_key, &input[12..32]);
                assert_eq!(server_hash[..4], input[32..36]);
                let mut chain = Chain::new(
                    kind,
                    &f.base,
                    &user_key,
                    f.user.id,
                    iv,
                    Auth {
                        client_id: [0; 4],
                        connection_id: 0,
                    },
                    0,
                    f.sizes.clone(),
                );
                chain.server = true;
                chain.sent_header = true;
                chain.tx.hash = server_hash;
                chain.tx.rc4 = rc4_for(&user_key, &hash0);
                chain.rx.hash = hash0;
                chain.rx.rc4 = rc4_for(&user_key, &hash0);
                input.advance(36);
                self.state = Some(ProtocolLayer::Chain(Box::new(chain)));
            }
        }
        Ok(())
    }
}

impl Layer for ServerProtocol {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        self.state.as_mut().unwrap().encode(out, data)
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        if self.state.is_none() {
            self.open_header(input, decoded)?;
        }
        match self.state.as_mut() {
            Some(state) => state.decode(input, decoded, reply),
            None => Ok(()),
        }
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        unreachable!("the test server is never split")
    }
}

pub(crate) struct Fixture {
    pub cipher: SsrCipher,
    pub factory: Arc<ProtocolFactory>,
    pub obfs: crate::ssr::obfs::ObfsFactory,
}

pub(crate) async fn serve_tcp(listener: TcpListener, fixture: Arc<Fixture>) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let fixture = fixture.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(socket, &fixture).await {
                eprintln!("server: {err}");
            }
        });
    }
}

async fn handle(socket: tokio::net::TcpStream, fixture: &Fixture) -> io::Result<()> {
    let peer_iv: SharedIv = Arc::default();
    let obfs = CodecStream::new(socket, super::server_obfs::layer(&fixture.obfs));
    let cipher = CodecStream::new(
        obfs,
        ServerCipher {
            inner: fixture.cipher.layer().unwrap(),
            iv_len: fixture.cipher.iv_len(),
            peer_iv: peer_iv.clone(),
            seen: false,
        },
    );
    let mut stream = CodecStream::new(
        cipher,
        ServerProtocol {
            factory: fixture.factory.clone(),
            peer_iv,
            state: None,
        },
    );
    let mut head = Vec::new();
    let _target = loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
        if let Some((addr, used)) = SOCKS.parse(&head)? {
            assert_eq!(used, head.len());
            break addr;
        }
    };
    let mut buf = vec![0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return stream.shutdown().await;
        }
        stream.write_all(&buf[..n]).await?;
        stream.flush().await?;
    }
}

pub(crate) async fn serve_udp(socket: UdpSocket, fixture: Arc<Fixture>) {
    let protocol = fixture.factory.packet();
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let mut pkt = PacketBuf::with_headroom(64);
        pkt.extend_from_slice(&buf[..n]);
        fixture.cipher.open_packet(&mut pkt).unwrap();
        match &protocol {
            PacketProtocol::Plain => {}
            PacketProtocol::Aes { hash, user_key, .. } => {
                let len = pkt.len();
                assert_eq!(
                    hmac(*hash, user_key, &pkt.as_slice()[..len - 4])[..4],
                    pkt.as_slice()[len - 4..]
                );
                pkt.truncate(len - 8);
            }
            PacketProtocol::Chain { key, user_key, .. } => {
                let len = pkt.len();
                let data = pkt.as_slice();
                assert_eq!(hmac_md5(user_key, &data[..len - 1])[..1], data[len - 1..]);
                let md5 = hmac_md5(key, &data[len - 8..len - 5]);
                pkt.truncate(len - 8 - udp_rand_len(&md5));
                rc4_for(user_key, &md5).apply(pkt.as_mut_slice());
            }
        }
        let (addr, used) = SOCKS.parse(pkt.as_slice()).unwrap().unwrap();
        pkt.consume(used);
        let mut reply = PacketBuf::with_headroom(64);
        let mut head = Vec::new();
        SOCKS.write(&addr, &mut head).unwrap();
        reply.extend_from_slice(&head);
        reply.extend_from_slice(pkt.as_slice());
        match &protocol {
            PacketProtocol::Plain => {}
            PacketProtocol::Aes { hash, key, .. } => {
                let mac = hmac(*hash, key, reply.as_slice());
                reply.extend_from_slice(&mac[..4]);
            }
            PacketProtocol::Chain { key, user_key, .. } => {
                let mut tail = [0u8; 7];
                rand::fill(&mut tail[..]);
                let md5 = hmac_md5(key, &tail);
                rc4_for(user_key, &md5).apply(reply.as_mut_slice());
                reply.extend_from_slice(&vec![3u8; udp_rand_len(&md5)]);
                reply.extend_from_slice(&tail);
                let mac = hmac_md5(user_key, reply.as_slice());
                reply.extend_from_slice(&mac[..1]);
            }
        }
        fixture.cipher.seal_packet(&mut reply).unwrap();
        let _ = socket.send_to(reply.as_slice(), from).await;
    }
}
