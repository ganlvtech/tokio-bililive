use tokio_bililive::{Client, Message};
use tokio_bililive::messages::danmu_msg::DanmuMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let room_id = 2029840;
    let mut client = Client::new_anonymous(room_id).await?;
    println!("Room {} Connected", room_id);
    loop {
        let message = client.next().await?;
        match message {
            Message::OpHeartbeatReply(v) => {
                println!("Room {} Popularity: {}", room_id, v.popularity);
            }
            Message::OpMessage(v) => {
                match v.cmd.as_str() {
                    "DANMU_MSG" => {
                        let v = serde_json::from_slice::<DanmuMsg>(&v.data)?;
                        println!("Room {} Danmaku: [{}|{}] {}: {}", room_id, v.fans_medal_name(), v.fans_medal_level(), v.uname(), v.msg());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(())
}
