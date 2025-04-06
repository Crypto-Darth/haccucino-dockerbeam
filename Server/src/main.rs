use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use futures_util::{StreamExt, SinkExt};
use std::{collections::HashSet, net::SocketAddr};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use serde::{Deserialize, Serialize};
use base64;
use tokio_tungstenite::tungstenite::protocol::Message;
use futures_util::stream::{SplitSink, SplitStream};
use tokio_tungstenite::WebSocketStream;
use tokio::net::TcpStream;

use std::fs::File;
use std::io::BufReader;
use tokio_rustls::{rustls, TlsAcceptor};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// transfer was done ,offer done-ish , start with applying offer and get answer then ICE candidates then peering up......
// hmmm


#[derive(Serialize, Deserialize, Debug)]
struct Msg {
    code: String,
    id:String,
    data: String,
}

//Arc<tokio::sync::Mutex<SplitSink<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, _>>>

type WriteStream = Arc<Mutex<SplitSink<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, Message>>>;
type ReadStream = Arc<Mutex<SplitStream<WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>>;

// Simplified LookupMap type
type LookupMap = Arc<Mutex<HashMap<String, (WriteStream, ReadStream)>>>;
type PairMap = Arc<Mutex<HashMap<String, String>>>;
type PeerSet = Arc<Mutex<HashSet<(String, String)>>>;

#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>>{
    println!("Server Starting up \n\n");



    let addr = "0.0.0.0:10000".parse::<SocketAddr>().unwrap();
    //let listener = TcpListener::bind(&addr).await.expect("Failed to start");

    let certs = CertificateDer::pem_file_iter(std::path::PathBuf::from("fullchain.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(std::path::PathBuf::from("privatekey.pem"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;



    let lookup: LookupMap = Arc::new(Mutex::new(HashMap::new()));
    let requests: PairMap = Arc::new(Mutex::new(HashMap::new()));
    let peered: PeerSet = Arc::new(Mutex::new(HashSet::new()));

    println!("WebSocket server listening on wss://{}", addr);

    // while let Ok((stream, addr)) = listener.accept().await {
    //     let lookup = lookup.clone();
    //     let requests = requests.clone();
    //     let peered = peered.clone();
    //     tokio::spawn(async move {
    //         conn_handler(addr, stream, lookup, requests, peered).await;
    //     });
    // };
    // Ok(())

    // while let Ok((stream, addr)) = listener.accept().await {
    //     let acceptor = acceptor.clone();
    //     let lookup = lookup.clone();
    //     let requests = requests.clone();
    //     let peered = peered.clone();

    //     tokio::spawn(async move {
    //         match acceptor.accept(stream).await {
    //             Ok(tls_stream) => {
    //                 if let Err(e) = accept_async(tls_stream).await {
    //                     eprintln!("WebSocket handshake failed: {}", e);
    //                 } else {
    //                     conn_handler(addr, tls_stream, lookup, requests, peered).await;
    //                 }
    //             }
    //             Err(e) => eprintln!("TLS handshake failed: {}", e),
    //         }
    //     });
    // }

    while let Ok((stream, addr)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let lookup = lookup.clone();
        let requests = requests.clone();
        let peered = peered.clone();
    
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // Pass ownership of tls_stream directly to conn_handler
                    conn_handler(addr, tls_stream, lookup, requests, peered).await;
                }
                Err(e) => eprintln!("TLS handshake failed: {}", e),
            }
        });
    }

    Ok(())
}

async fn conn_handler(addr: SocketAddr, stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream> , lookup: LookupMap, requests: PairMap, peered: PeerSet){
    let ws_stream = accept_async(stream).await.expect("Failed WebSocket handshake");
    println!("New WebSocket connection from {}", addr.ip());

    // Move write and read into Arc<Mutex<_>> outside the loop
    let (write, read) = ws_stream.split();
    let write = Arc::new(Mutex::new(write));
    let read = Arc::new(Mutex::new(read));

    while let Some(init_msg) = read.lock().await.next().await {
        let msg = match serde_json::from_str::<Msg>(init_msg.expect("yuhh").to_text().unwrap()) {
            Ok(msg) => msg,
            Err(e) => {
                println!("Failed to parse message: {:?}", e);
                return;
            }
        };
        println!("\nmsg - {}",msg.id);
        println!("\nmsg - {}",msg.code);
        println!("\nmsg - {}\n\n",msg.data);



        match msg.code.as_str() { 
            "server" => {
                let cryptic = base64::encode(addr.ip().to_string());
                println!("Generated Cryptic Hash: {:?}", cryptic);

                let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

                lookup.lock().await.insert(cryptic.clone(), (write.clone(), read.clone()));

                let resvId = Msg{
                    id:cryptic,
                    code:"Reservation_id".to_string(),
                    data:"null".to_string()
                };
                // Notify client of cryptic code
                let _ = tx.send(Message::Text(serde_json::to_string(&resvId).unwrap()));

                tokio::spawn({
                    let write = write.clone();
                    async move {
                        while let Some(msg) = rx.recv().await {
                            let mut write = write.lock().await;
                            if let Err(e) = write.send(msg).await {
                                println!("Error sending message: {:?}", e);
                                break;
                            }
                        }
                    }
                });
            },
            "server-accept" => {
                println!("server accepted");

                let find = msg.id;
                let find2 = msg.data;
                println!("find  {find:?}");
                if let Some(client_id) = requests.lock().await.get(&find) {
                    println!("conf guarenteed");
                    let _ = peered.lock().await.insert((find.clone(),find2.clone()));
                    let ret_msg :Msg = Msg { code: "server-accepted".to_string(), id: client_id.clone(), data: find2.clone() };
                    let xy = lookup.lock().await;
                    println!("lookup - {lookup:?}");
                    let (ws_write,_ws_read) = xy.get(&find2).unwrap(); //change this to client type arc::clone shit incase doesnt work
                    let _ = ws_write.lock().await.send(Message::Text(serde_json::to_string(&ret_msg).unwrap())).await;
                    // Clone Arc pointers to ensure they can be used in the async block
                    // let write1 = Arc::clone(write1);
                    // let write2 = Arc::clone(write2);
                    // let read1 = Arc::clone(read1);
                    // let read2 = Arc::clone(read2);
                
                } else {
                    println!("Not found");
                }
            },
            "client" => {
                let find = msg.id;

                let (ws_write, _ws_read) = if let Some((write, read)) = lookup.lock().await.get(&find) {
                    

                    (Arc::clone(write), Arc::clone(read))
                } else {
                    println!("Client ID not found. {find:?}");
                    send_err(write,"Client ID does not exist.").await;
                    return;
                };
                let newid = find.clone()+"-"+&base64::encode(addr.ip().to_string());
                println!("new id - {newid:?}");
                lookup.lock().await.insert(newid.clone(), (write.clone(), read.clone()));
                requests.lock().await.insert(find.clone(),newid.clone());
                let conf_msg = Msg{
                    id:find.clone(),
                    code:"confirmation".to_string(),
                    data:newid.clone()
                };

                let relay_message = Message::Text(serde_json::to_string(&conf_msg).unwrap());
                let mut ws_write = ws_write.lock().await;
                if let Err(e) = ws_write.send(relay_message).await {
                    println!("Error sending relay message: {:?}", e);
                } else {
                    println!("Relay message sent successfully.");
                }
            },
            "forward"=>{
                println!("server forward");

                let find = msg.id;
                println!("finding forward  {find:?}");
                let x_ = peered.lock().await;
                let other_id = x_
                .iter()
                .find(|(x, y)| x == &find || y == &find)
                .map(|(x, y)| {
                    if x == &find { y.clone() } else { x.clone() }
                })
                .unwrap();
                println!("other id {other_id:?}");
                let xy = lookup.lock().await;
                let (ws_write,_ws_read) = xy.get(&other_id).unwrap(); //change this to client type arc::clone shit incase doesnt work
                let _ = ws_write.lock().await.send(Message::Text(serde_json::to_string(&Msg{code:"forward".to_string(),id:other_id.clone(),data:msg.data}).unwrap())).await;

                // if let Some(((write1, read1), (write2, read2))) = requests.lock().await.get(&find) {
                //     println!("found");

                //     println!("reacdhed");
                
                // } else {
                //     println!("Not found");
                // }
            },
            "disconnect" => {
                println!("Client requested disconnect.");
                // Implement disconnect logic as needed.
            },
            _ => {
                println!("Unknown code received: {}", msg.code);
            }
        }
    }
}

async fn send_err(writer:WriteStream,s:&str){
    let mut wx = writer.lock().await;
    let _ = wx.send(Message::Text(serde_json::to_string(&Msg{
        code:"err".to_string(),
        id:"NULL".to_string(),
        data:s.to_string()
    }).unwrap())).await;
    wx.close().await;
}