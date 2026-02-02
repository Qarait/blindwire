use blindwire_server::run_server;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let addr = "0.0.0.0:8080";
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Signaling server listening on: {}", addr);
    run_server(listener).await;
}
