use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use brotli_decompressor::BrotliDecompress;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use inflate::inflate_bytes_zlib;
use reqwest::cookie::Jar;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::net::tcp::OwnedReadHalf;

// region Packet

pub const BODY_PROTOCOL_VERSION_NORMAL: u16 = 0;
pub const BODY_PROTOCOL_VERSION_POPULARITY: u16 = 1;
pub const BODY_PROTOCOL_VERSION_DEFLATE: u16 = 2;
pub const BODY_PROTOCOL_VERSION_BROTLI: u16 = 3;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: u16,
    pub op: u32,
    pub seq: u32,
    pub data: Vec<u8>,
}

impl Packet {
    pub const MAX_PACKET_LEN: u32 = 65535;
    pub const HEADER_LEN: u16 = 16;

    pub fn from_reader<R: Read>(r: &mut R) -> anyhow::Result<Self> {
        let packet_len = r.read_u32::<BigEndian>()?;
        if packet_len > Self::MAX_PACKET_LEN {
            return Err(anyhow!("packet too long. packet_len: {}", packet_len));
        }
        let header_len = r.read_u16::<BigEndian>()?;
        if header_len != Self::HEADER_LEN {
            return Err(anyhow!("header_len != {}. header_len: {}", Self::HEADER_LEN, header_len));
        }
        let version = r.read_u16::<BigEndian>()?;
        let op = r.read_u32::<BigEndian>()?;
        let seq = r.read_u32::<BigEndian>()?;
        let data_len = packet_len as usize - header_len as usize;
        let mut data = vec![0; data_len];
        r.read_exact(&mut data)?;
        Ok(Self {
            version,
            op,
            seq,
            data,
        })
    }

    pub fn to_writer<W: Write>(&self, w: &mut W) -> anyhow::Result<()> {
        let packet_len = self.data.len() as u32 + Self::HEADER_LEN as u32;
        w.write_u32::<BigEndian>(packet_len)?;
        w.write_u16::<BigEndian>(Self::HEADER_LEN)?;
        w.write_u16::<BigEndian>(self.version)?;
        w.write_u32::<BigEndian>(self.op)?;
        w.write_u32::<BigEndian>(self.seq)?;
        w.write(&self.data)?;
        Ok(())
    }

    pub async fn from_async_reader<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Self> {
        let packet_len = r.read_u32().await?;
        if packet_len > Self::MAX_PACKET_LEN {
            return Err(anyhow!("packet too long. packet_len: {}", packet_len));
        }
        let header_len = r.read_u16().await?;
        if header_len != Self::HEADER_LEN {
            return Err(anyhow!("header_len != {}. header_len: {}", Self::HEADER_LEN, header_len));
        }
        let version = r.read_u16().await?;
        let op = r.read_u32().await?;
        let seq = r.read_u32().await?;
        let data_len = packet_len as usize - header_len as usize;
        let mut data = vec![0; data_len];
        r.read_exact(&mut data).await?;
        Ok(Self {
            version,
            op,
            seq,
            data,
        })
    }

    pub async fn to_async_writer<W: AsyncWrite + Unpin>(&self, w: &mut W) -> anyhow::Result<()> {
        let packet_len = self.data.len() as u32 + Self::HEADER_LEN as u32;
        w.write_u32(packet_len).await?;
        w.write_u16(Self::HEADER_LEN).await?;
        w.write_u16(self.version).await?;
        w.write_u32(self.op).await?;
        w.write_u32(self.seq).await?;
        w.write(&self.data).await?;
        w.flush().await?;
        Ok(())
    }

    pub fn into_value(self) -> anyhow::Result<PacketValue> {
        Ok(match self.version {
            BODY_PROTOCOL_VERSION_NORMAL => PacketValue::Operation(RawMessage {
                op: self.op,
                data: self.data,
            }),
            BODY_PROTOCOL_VERSION_POPULARITY => PacketValue::Popularity(read_u32(&self.data)?),
            BODY_PROTOCOL_VERSION_DEFLATE => PacketValue::Packets(decode_packets(&zlib_decode_bytes(&self.data)?)?),
            BODY_PROTOCOL_VERSION_BROTLI => PacketValue::Packets(decode_packets(&brotli_decode_bytes(&self.data)?)?),
            _ => return Err(anyhow!("Unknown packet version {}", self.version)),
        })
    }

    pub fn into_value_recursive(self) -> anyhow::Result<Vec<PacketValue>> {
        let mut results = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(self);
        while let Some(packet) = queue.pop_front() {
            let value = packet.into_value()?;
            if value.is_packets() {
                match value {
                    PacketValue::Packets(v) => v.into_iter().for_each(|v| queue.push_back(v)),
                    _ => {}
                }
            } else {
                results.push(value);
            }
        }
        Ok(results)
    }

    pub fn into_raw_messages(self) -> anyhow::Result<Vec<RawMessage>> {
        let mut results = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(self);
        while let Some(packet) = queue.pop_front() {
            match packet.into_value()? {
                PacketValue::Operation(v) => results.push(v),
                PacketValue::Popularity(_) => {}
                PacketValue::Packets(v) => v.into_iter().for_each(|v| queue.push_back(v)),
            }
        }
        Ok(results)
    }

    pub fn into_messages(self) -> anyhow::Result<Vec<Message>> {
        Ok(self.into_raw_messages()?.into_iter().filter_map(|v| v.into_message().ok()).collect())
    }

    pub fn new_user_authentication(room_id: i32, uid: i32, token: String) -> anyhow::Result<Self> {
        Ok(Self {
            version: 0,
            op: OP_USER_AUTHENTICATION,
            seq: 0,
            data: serde_json::to_vec(&OpUserAuthentication {
                uid,
                roomid: room_id,
                protover: 3,
                platform: "web".to_string(),
                r#type: 2,
                key: token,
            })?,
        })
    }

    pub fn new_heartbeat(seq: u32) -> Self {
        Self {
            version: 0,
            op: OP_HEARTBEAT,
            seq,
            data: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketValue {
    Operation(RawMessage),
    Popularity(u32),
    Packets(Vec<Packet>),
}

impl PacketValue {
    pub fn is_packets(&self) -> bool {
        match self {
            PacketValue::Operation(_) => false,
            PacketValue::Popularity(_) => false,
            PacketValue::Packets(_) => true,
        }
    }
}

fn brotli_decode_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    BrotliDecompress(&mut Cursor::new(input), &mut Cursor::new(&mut output))?;
    Ok(output)
}

fn zlib_decode_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(match inflate_bytes_zlib(input) {
        Ok(output) => output,
        Err(e) => return Err(anyhow!("zlib decode error: {}", e)),
    })
}

fn decode_packets(data: &[u8]) -> anyhow::Result<Vec<Packet>> {
    let mut r = Cursor::new(data);
    let mut packets = Vec::new();
    while (r.position() as usize) < data.len() {
        let packet = Packet::from_reader(&mut r)?;
        packets.push(packet);
    }
    Ok(packets)
}

fn read_u32(data: &[u8]) -> anyhow::Result<u32> {
    Ok(u32::from_be_bytes(data[..4].try_into()?))
}

// endregion

// region RawMessage

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RawMessage {
    pub op: u32,
    pub data: Vec<u8>,
}

impl RawMessage {
    pub fn into_message(self) -> anyhow::Result<Message> {
        Ok(match self.op {
            OP_HEARTBEAT => Message::OpHeartbeat,
            OP_HEARTBEAT_REPLY => Message::OpHeartbeatReply(OpHeartbeatReply { popularity: read_u32(&self.data)? }),
            OP_MESSAGE => {
                let op_message_cmd = serde_json::from_slice::<OpMessageCmd>(&self.data)?;
                Message::OpMessage(Box::new(OpMessage {
                    cmd: op_message_cmd.cmd,
                    data: self.data,
                }))
            }
            OP_USER_AUTHENTICATION => Message::OpUserAuthentication(Box::new(serde_json::from_slice(&self.data)?)),
            OP_CONNECT_SUCCESS => Message::OpConnectSuccess(serde_json::from_slice(&self.data)?),
            _ => return Err(anyhow!("Unknown op {}", self.op)),
        })
    }
    pub fn into_packet(self, seq: u32) -> Packet {
        Packet {
            version: BODY_PROTOCOL_VERSION_NORMAL,
            op: self.op,
            seq,
            data: self.data,
        }
    }
}

// endregion

// region Message

pub const OP_HEARTBEAT: u32 = 2;
pub const OP_HEARTBEAT_REPLY: u32 = 3;
pub const OP_MESSAGE: u32 = 5;
pub const OP_USER_AUTHENTICATION: u32 = 7;
pub const OP_CONNECT_SUCCESS: u32 = 8;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OpHeartbeatReply {
    pub popularity: u32,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct OpMessageCmd {
    pub cmd: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OpMessage {
    pub cmd: String,
    pub data: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OpUserAuthentication {
    pub uid: i32,
    pub roomid: i32,
    pub protover: i32,
    pub platform: String,
    pub r#type: i32,
    pub key: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OpConnectSuccess {
    pub code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // 2 C -> S
    OpHeartbeat,
    // 3 S -> C
    OpHeartbeatReply(OpHeartbeatReply),
    // 5 S -> C
    OpMessage(Box<OpMessage>),
    // 7 C -> S
    OpUserAuthentication(Box<OpUserAuthentication>),
    // 8 S -> C
    OpConnectSuccess(OpConnectSuccess),
}

impl Message {
    pub fn to_raw_message(&self) -> anyhow::Result<RawMessage> {
        Ok(match self {
            Message::OpHeartbeat => RawMessage { op: OP_HEARTBEAT, data: Default::default() },
            Message::OpHeartbeatReply(v) => RawMessage { op: OP_HEARTBEAT_REPLY, data: v.popularity.to_be_bytes().into() },
            Message::OpMessage(v) => RawMessage { op: OP_MESSAGE, data: serde_json::to_vec(v)? },
            Message::OpUserAuthentication(v) => RawMessage { op: OP_USER_AUTHENTICATION, data: serde_json::to_vec(v)? },
            Message::OpConnectSuccess(v) => RawMessage { op: OP_CONNECT_SUCCESS, data: serde_json::to_vec(v)? },
        })
    }
}

// endregion

// region Client

pub struct Client {
    is_run: Arc<AtomicBool>,
    r: BufReader<OwnedReadHalf>,
    queue: VecDeque<Message>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.is_run.store(false, Ordering::Relaxed);
    }
}

impl Client {
    async fn heartbeat<W: AsyncWrite + Unpin>(mut w: W, duration: Duration, is_run: Arc<AtomicBool>) -> anyhow::Result<()> {
        let mut seq = 1;
        while is_run.load(Ordering::Relaxed) {
            Packet::new_heartbeat(seq).to_async_writer(&mut w).await?;
            seq += 1;
            tokio::time::sleep(duration).await;
        }
        Ok(())
    }

    pub async fn new<A: ToSocketAddrs>(room_id: i32, addr: A, uid: i32, token: String) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let (rx, tx) = stream.into_split();
        let r = BufReader::new(rx);
        let mut w = BufWriter::new(tx);
        // 进房
        Packet::new_user_authentication(room_id, uid, token)?.to_async_writer(&mut w).await?;
        // 心跳
        let is_run = Arc::new(AtomicBool::new(true));
        tokio::spawn(Self::heartbeat(w, Duration::from_secs(30), is_run.clone()));
        Ok(Self {
            is_run,
            r,
            queue: Default::default(),
        })
    }

    pub async fn new_with_config(room_id: i32, uid: i32, config: RoomConfigResponse) -> anyhow::Result<Self> {
        let item = config.data.host_server_list.get(0).ok_or(anyhow!("empty host_server_list"))?;
        let addr = format!("{}:{}", item.host, item.port);
        let token = config.data.token;
        Self::new(room_id, addr, uid, token).await
    }

    pub async fn new_anonymous(room_id: i32) -> anyhow::Result<Self> {
        Self::new(room_id, "broadcastlv.chat.bilibili.com:2243".to_string(), 0, "".to_string()).await
    }

    async fn fill_queue(&mut self) -> anyhow::Result<()> {
        while self.queue.is_empty() {
            let packet = Packet::from_async_reader(&mut self.r).await?;
            let messages = packet.into_messages()?;
            if messages.is_empty() {
                continue;
            }
            self.queue = VecDeque::from(messages);
        }
        Ok(())
    }

    pub async fn next(&mut self) -> anyhow::Result<Message> {
        self.fill_queue().await?;
        Ok(self.queue.pop_front().expect("fill_queue must wait the queue with at lease"))
    }
}

// endregion

// region DanmakuConfig

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfigResponse {
    pub code: i64,
    pub msg: String,
    pub message: String,
    pub data: RoomConfig,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfig {
    pub refresh_row_factor: f64,
    pub refresh_rate: i64,
    pub max_delay: i64,
    pub port: i64,
    pub host: String,
    pub host_server_list: Vec<RoomConfigHostServerList>,
    pub server_list: Vec<RoomConfigServerList>,
    pub token: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfigHostServerList {
    pub host: String,
    pub port: i64,
    pub wss_port: i64,
    pub ws_port: i64,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RoomConfigServerList {
    pub host: String,
    pub port: i64,
}

impl RoomConfigResponse {
    pub async fn from_room_id(room_id: i32) -> anyhow::Result<RoomConfigResponse> {
        Ok(reqwest::get(&format!("https://api.live.bilibili.com/room/v1/Danmu/getConf?room_id={}&platform=pc&player=web", room_id))
            .await?
            .json()
            .await?)
    }
}

// endregion

// region SendDanmakuResponse

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SendDanmakuResponse {
    pub code: i64,
    pub data: SendDanmakuResponseData,
    pub message: String,
    pub msg: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SendDanmakuResponseData {
    pub mode_info: SendDanmakuResponseDataModeInfo,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SendDanmakuResponseDataModeInfo {
    pub mode: i64,
    pub show_player_type: i64,
    pub extra: String,
}

// endregion

// region ApiClient

#[derive(Debug, Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    bili_jct: String,
}

impl ApiClient {
    pub fn new(sess_data: String, bili_jct: String) -> Self {
        let jar = Jar::default();
        jar.add_cookie_str(&format!("SESSDATA={}", sess_data), &"https://api.live.bilibili.com".parse().unwrap());
        jar.add_cookie_str(&format!("bili_jct={}", bili_jct), &"https://api.live.bilibili.com".parse().unwrap());
        let client = reqwest::Client::builder()
            .cookie_provider(Arc::new(jar))
            .build()
            .unwrap();
        Self {
            client,
            bili_jct,
        }
    }

    pub async fn get_room_config(&self, room_id: i32) -> anyhow::Result<RoomConfigResponse> {
        Ok(self.client.get(&format!("https://api.live.bilibili.com/room/v1/Danmu/getConf?room_id={}&platform=pc&player=web", room_id))
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn send_danmaku(&self, room_id: i32, msg: String) -> anyhow::Result<SendDanmakuResponse> {
        Ok(self.client.post("https://api.live.bilibili.com/msg/send")
            .form(&HashMap::from([
                ("bubble", "0".to_string()),
                ("msg", msg),
                ("color", "16777215".to_string()),
                ("mode", "1".to_string()),
                ("fontsize", "25".to_string()),
                ("rnd", get_timestamp().to_string()),
                ("roomid", room_id.to_string()),
                ("csrf", self.bili_jct.clone()),
                ("csrf_token", self.bili_jct.clone()),
            ]))
            .send()
            .await?
            .json()
            .await?)
    }

    pub fn get_client(&self) -> reqwest::Client {
        self.client.clone()
    }
}

fn get_timestamp() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() }

// endregion

pub mod messages {
    pub mod danmu_msg {
        use serde::{Deserialize, Serialize};
        use serde_json::Value;

        #[derive(Default, Debug, Clone, Serialize, Deserialize)]
        pub struct DanmuMsg {
            pub cmd: String,
            pub info: Vec<Value>,
        }

        impl DanmuMsg {
            pub fn msg(&self) -> String {
                if let Some(v) = self.info.get(1) {
                    if let Some(v) = v.as_str() {
                        return v.to_owned();
                    }
                }
                return "".to_string();
            }
            pub fn uid(&self) -> i64 {
                if let Some(v) = self.info.get(2) {
                    if let Some(v) = v.get(0) {
                        if let Some(v) = v.as_i64() {
                            return v;
                        }
                    }
                }
                return 0;
            }
            pub fn uname(&self) -> String {
                if let Some(v) = self.info.get(2) {
                    if let Some(v) = v.get(1) {
                        if let Some(v) = v.as_str() {
                            return v.to_owned();
                        }
                    }
                }
                return "".to_string();
            }
            pub fn fans_medal_level(&self) -> i64 {
                if let Some(v) = self.info.get(3) {
                    if let Some(v) = v.get(0) {
                        if let Some(v) = v.as_i64() {
                            return v;
                        }
                    }
                }
                return 0;
            }
            pub fn fans_medal_name(&self) -> String {
                if let Some(v) = self.info.get(3) {
                    if let Some(v) = v.get(1) {
                        if let Some(v) = v.as_str() {
                            return v.to_owned();
                        }
                    }
                }
                return "".to_string();
            }
            pub fn fans_medal_uname(&self) -> String {
                if let Some(v) = self.info.get(3) {
                    if let Some(v) = v.get(2) {
                        if let Some(v) = v.as_str() {
                            return v.to_owned();
                        }
                    }
                }
                return "".to_string();
            }
            pub fn fans_medal_room_id(&self) -> i64 {
                if let Some(v) = self.info.get(3) {
                    if let Some(v) = v.get(3) {
                        if let Some(v) = v.as_i64() {
                            return v;
                        }
                    }
                }
                return 0;
            }
            pub fn fans_medal_uid(&self) -> i64 {
                if let Some(v) = self.info.get(3) {
                    if let Some(v) = v.get(12) {
                        if let Some(v) = v.as_i64() {
                            return v;
                        }
                    }
                }
                return 0;
            }
            pub fn timestamp_ms(&self) -> i64 {
                if let Some(v) = self.info.get(0) {
                    if let Some(v) = v.get(4) {
                        if let Some(v) = v.as_i64() {
                            return v;
                        }
                    }
                }
                return 0;
            }
        }
    }
}
