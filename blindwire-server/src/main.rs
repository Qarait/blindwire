use blindwire_server::run_server;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let addr =
        std::env::var("BLINDWIRE_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    println!("Signaling server listening on: {addr}");
    run_server(listener).await;
}
