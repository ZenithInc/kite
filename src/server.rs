use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

mod common;
mod crypto;

use common::*;
use crypto::Crypto;

#[derive(Clone)]
struct ProxyServer {
    crypto: Arc<Crypto>,
    client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl ProxyServer {
    fn new(auth_key: String) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder().build::<_, hyper::Body>(https);

        Self {
            crypto: Arc::new(Crypto::new(&auth_key)),
            client,
        }
    }

    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        // 检查是否是CONNECT请求
        if req.method() == Method::CONNECT {
            match self.handle_connect_tunnel(req).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!("Error handling CONNECT: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("Bad Gateway"))
                        .unwrap())
                }
            }
        } else {
            match self.process_request(req).await {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!("Error processing request: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Internal Server Error"))
                        .unwrap())
                }
            }
        }
    }
    async fn handle_connect_tunnel(&self, req: Request<Body>) -> Result<Response<Body>> {
        let host = req.uri().host().ok_or_else(|| anyhow::anyhow!("No host in CONNECT request"))?;
        let port = req.uri().port_u16().unwrap_or(443);
        let addr = format!("{}:{}", host, port);

        info!("CONNECT tunnel to {}", addr);

        // 尝试连接到目标服务器（带超时）
        let server_stream = match timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr)
        ).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                stream
            },
            Ok(Err(e)) => {
                error!("Failed to connect to {}: {}", addr, e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Bad Gateway"))
                    .unwrap());
            }
            Err(_) => {
                error!("Connection timeout to {}", addr);
                return Ok(Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(Body::from("Gateway Timeout"))
                    .unwrap());
            }
        };

        // ✅ 关键修复：在返回响应之前获取升级 future
        let upgrade_future = hyper::upgrade::on(req);

        // 启动隧道任务
        tokio::spawn(async move {
            match upgrade_future.await {
                Ok(client_stream) => {
                    info!("Starting tunnel for {}", addr);
                    if let Err(e) = Self::tunnel(client_stream, server_stream).await {
                        error!("Tunnel error for {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("Failed to upgrade connection: {}", e);
                }
            }
        });

        // 返回标准的 CONNECT 响应
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())?)
    }
    

    // 创建双向隧道
    async fn tunnel(client: Upgraded, server: TcpStream) -> anyhow::Result<()> {
        // 直接使用 Tokio 内置的 copy_bidirectional
        let (mut client, mut server) = (client, server);
        match io::copy_bidirectional(&mut client, &mut server).await {
            Ok((from_c, from_s)) => {
                info!("tunnel closed, c→s {} bytes, s→c {} bytes", from_c, from_s);
            }
            Err(e) => error!("tunnel error: {}", e),
        }
        Ok(())
    }
    async fn process_request(&self, mut req: Request<Body>) -> Result<Response<Body>> {
        // 验证请求是否来自我们的客户端
        if !self.verify_request(&req) {
            warn!("Unauthorized request");
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized"))
                .unwrap());
        }

        // 检查是否是加密的CONNECT请求
        if let Some(connect_addr) = req.headers().get("X-Proxy-Connect") {
            let addr = connect_addr.to_str()?.to_string();
            info!("Handling encrypted CONNECT request for {}", addr);

            // 先标记升级
            let upgraded = hyper::upgrade::on(&mut req);

            // 先连接目标服务器（带超时）
            let server_stream = match timeout(
                Duration::from_secs(10),
                TcpStream::connect(&addr)
            ).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                },
                Ok(Err(e)) => {
                    error!("Failed to connect to {}: {}", addr, e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("Bad Gateway"))
                        .unwrap());
                }
                Err(_) => {
                    error!("Connection timeout to {}", addr);
                    return Ok(Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .body(Body::from("Gateway Timeout"))
                        .unwrap());
                }
            };

            tokio::spawn(async move {
                match upgraded.await {
                    Ok(client_stream) => {
                        info!("Starting encrypted tunnel to {}", addr);
                        if let Err(e) = Self::tunnel(client_stream, server_stream).await {
                            error!("Encrypted tunnel error for {}: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to upgrade encrypted connection: {}", e);
                    }
                }
            });

            return Ok(
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)   // ← 101
                    .header("Connection", "Upgrade")
                    .header("Upgrade", "tcp")
                    .body(Body::empty())?
            );
        }

        // 解密请求体
        let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
        let decrypted = self.crypto.decrypt(&body_bytes)?;
        let proxy_req: ProxyRequest = serde_json::from_slice(&decrypted)?;

        info!("Proxying request: {} {}", proxy_req.method, proxy_req.url);

        // 构建转发请求
        let method = proxy_req.method.parse::<Method>()?;
        let mut forward_req = Request::builder().method(method).uri(&proxy_req.url);

        // 添加头部
        for (key, value) in proxy_req.headers {
            forward_req = forward_req.header(&key, &value);
        }

        let body = proxy_req.body.unwrap_or_default();
        let forward_req = forward_req.body(Body::from(body))?;

        // 发送请求（带超时）
        let response = match timeout(
            Duration::from_secs(30),
            self.client.request(forward_req)
        ).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                error!("Request failed: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Bad Gateway"))
                    .unwrap());
            }
            Err(_) => {
                error!("Request timeout");
                return Ok(Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(Body::from("Gateway Timeout"))
                    .unwrap());
            }
        };

        let status = response.status().as_u16();

        // 收集响应头
        let mut headers = Vec::new();
        for (key, value) in response.headers() {
            headers.push((key.to_string(), value.to_str()?.to_string()));
        }

        // 读取响应体
        let response_body = hyper::body::to_bytes(response.into_body()).await?;

        // 构建代理响应
        let proxy_resp = ProxyResponse {
            id: proxy_req.id,
            status,
            headers,
            body: response_body.to_vec(),
        };

        // 加密响应
        let serialized = serde_json::to_vec(&proxy_resp)?;
        let encrypted = self.crypto.encrypt(&serialized)?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(encrypted))?)
    }

    fn verify_request(&self, req: &Request<Body>) -> bool {
        // 对于标准的CONNECT请求，不需要验证
        if req.method() == Method::CONNECT {
            return true;
        }

        // 对于加密的请求，验证认证头
        req.headers()
            .get("X-Proxy-Auth")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "proxy-rs")
            .unwrap_or(false)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_str = std::fs::read_to_string("config/server.toml").unwrap_or_else(|_| {
        r#"
bind_addr = "0.0.0.0:8080"
auth_key = "your-secret-key-here"
"#
            .to_string()
    });

    let config: ServerConfig = toml::from_str(&config_str)?;
    info!("Starting proxy server on {}", config.bind_addr);

    let proxy_server = ProxyServer::new(config.auth_key);

    let make_svc = make_service_fn(move |_conn| {
        let proxy_server = proxy_server.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let proxy_server = proxy_server.clone();
                async move { proxy_server.handle_request(req).await }
            }))
        }
    });

    let addr = config.bind_addr;
    let server = Server::bind(&addr)
        .tcp_nodelay(true)
        .serve(make_svc);

    info!("Proxy server running on http://{}", config.bind_addr);

    if let Err(e) = server.await {
        error!("Server error: {}", e);
    }

    Ok(())
}
