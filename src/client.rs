use anyhow::Result;
use futures::future::try_join;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

mod common;
mod crypto;

use common::*;
use crypto::Crypto;

#[derive(Clone)]
struct ProxyClient {
    server_addr: String,
    crypto: Arc<Crypto>,
    client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl ProxyClient {
    fn new(server_addr: String, auth_key: String) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder().build::<_, hyper::Body>(https);

        Self {
            server_addr,
            crypto: Arc::new(Crypto::new(&auth_key)),
            client,
        }
    }

    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        match self.process_request(req).await {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Error processing request: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Proxy Error"))
                    .unwrap())
            }
        }
    }

    async fn handle_connect(&self, mut req: Request<Body>) -> Result<Response<Body>> {
        // 1. 解析浏览器想连的 host:port
        let host = req.uri().host().ok_or_else(|| anyhow::anyhow!("CONNECT host missing"))?;
        let port = req.uri().port_u16().unwrap_or(443);
        let addr = format!("{host}:{port}");

        // 2. 先把浏览器这边的 on-upgrade 抓出来
        let browser_on_upgrade = hyper::upgrade::on(&mut req);

        // 3. 组装一条“升级到 tcp”的 HTTP 请求发往远端 proxy-server
        let connect_req = Request::builder()
            .method(Method::POST)                      // 也可以用 CONNECT，随意
            .uri(&self.server_addr)                    // 远端服务器地址，如 https://vps:8080
            .header("X-Proxy-Connect", &addr)          // 告诉服务器真正目标
            .header("X-Proxy-Auth", "proxy-rs")        // 简易认证
            .header("Connection", "Upgrade")
            .header("Upgrade", "tcp")
            .body(Body::empty())?;

        // 4. 把请求发出去，等待响应
        let mut resp = self.client.request(connect_req).await?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            // 既不是 101，就当失败
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("proxy server refused: {}", resp.status())))
                .unwrap());
        }

        // 5. 抓取服务器端的升级流
        let server_on_upgrade = hyper::upgrade::on(&mut resp);

        // 6. 启动后台任务：拿到两端流后 copy_bidirectional
        tokio::spawn(async move {
            match try_join(browser_on_upgrade, server_on_upgrade).await {
                Ok((mut browser_io, mut server_io)) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut browser_io, &mut server_io).await {
                        error!("tunnel {} error: {}", addr, e);
                    }
                }
                Err(e) => error!("upgrade failure {}: {}", addr, e),
            }
        });

        // 7. 返回给浏览器 200 Connection Established
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())?)
    }

    async fn process_request(&self, req: Request<Body>) -> Result<Response<Body>> {
        let method = req.method().to_string();
        let uri = req.uri().to_string();

        info!("Intercepting request: {} {}", method, uri);

        // Handle CONNECT method for HTTPS tunneling
        if req.method() == Method::CONNECT {
            return self.handle_connect(req).await;
        }

        // 收集请求头
        let mut headers = Vec::new();
        for (key, value) in req.headers() {
            headers.push((key.to_string(), value.to_str()?.to_string()));
        }

        // 读取请求体
        let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
        let body = if body_bytes.is_empty() {
            None
        } else {
            Some(body_bytes.to_vec())
        };

        // 构建代理请求
        let proxy_req = ProxyRequest {
            id: Uuid::new_v4().to_string(),
            method,
            url: uri,
            headers,
            body,
        };

        // 序列化并加密
        let serialized = serde_json::to_vec(&proxy_req)?;
        let encrypted = self.crypto.encrypt(&serialized)?;

        // 发送到代理服务器
        let server_req = Request::builder()
            .method(Method::POST)
            .uri(&self.server_addr)
            .header("Content-Type", "application/octet-stream")
            .header("X-Proxy-Auth", "proxy-rs")
            .body(Body::from(encrypted))?;

        let server_response = self.client.request(server_req).await?;

        if server_response.status() != StatusCode::OK {
            warn!("Server returned error: {}", server_response.status());
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Proxy server error"))
                .unwrap());
        }

        // 解密响应
        let response_bytes = hyper::body::to_bytes(server_response.into_body()).await?;
        let decrypted = self.crypto.decrypt(&response_bytes)?;
        let proxy_resp: ProxyResponse = serde_json::from_slice(&decrypted)?;

        // 构建最终响应
        let mut response_builder = Response::builder().status(proxy_resp.status);

        for (key, value) in proxy_resp.headers {
            response_builder = response_builder.header(&key, &value);
        }

        Ok(response_builder.body(Body::from(proxy_resp.body))?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_str = std::fs::read_to_string("config/client.toml").unwrap_or_else(|_| {
        r#"
            local_addr = "127.0.0.1:8888"
            server_addr = "https://your-server.com:8080"
            auth_key = "your-secret-key-here"
            mode = "Http"
            "#
        .to_string()
    });

    let config: ClientConfig = toml::from_str(&config_str)?;
    info!("Starting proxy client on {}", config.local_addr);

    let proxy_client = ProxyClient::new(config.server_addr, config.auth_key);

    let make_svc = make_service_fn(move |_conn| {
        let proxy_client = proxy_client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let proxy_client = proxy_client.clone();
                async move { proxy_client.handle_request(req).await }
            }))
        }
    });

    let server = Server::bind(&config.local_addr).serve(make_svc);

    info!("Proxy client running on http://{}", config.local_addr);
    info!("Set your HTTP proxy to: http://{}", config.local_addr);

    if let Err(e) = server.await {
        error!("Server error: {}", e);
    }

    Ok(())
}
