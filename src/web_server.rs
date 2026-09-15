use crate::config::WebServerConfig;
use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
    Router,
};
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use tower_http::services::ServeDir;
use tower::ServiceExt;

use tokio::io::{AsyncRead, AsyncWrite};

use std::sync::OnceLock;

static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    routes: Vec<WebServerConfig>,
    client: Client,
    client_ip: Option<std::net::IpAddr>,
}

pub async fn handle_web_server_connection<S>(tls_stream: S, routes: Vec<WebServerConfig>, client_ip: Option<std::net::IpAddr>) 
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Auto-tuning connection pool dynamically based on available system CPUs
    // If running on a 4 core system, we allow 100 idle connections per host by default,
    // scaling up to 1000 for high-end servers, ensuring maximum throughput.
    let client = HTTP_CLIENT.get_or_init(|| {
        let logical_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let max_idle = 100.max(logical_cpus * 50); // Auto-scaled tuning
        Client::builder()
            .pool_max_idle_per_host(max_idle)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap()
    }).clone();

    let state = AppState {
        routes,
        client,
        client_ip,
    };

    let app = Router::new()
        .fallback(dynamic_handler)
        .with_state(state);

    let hyper_service = hyper_util::service::TowerToHyperService::new(app);
    let io = TokioIo::new(tls_stream);

    let res = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, hyper_service)
        .await;
    
    if let Err(e) = res {
        tracing::error!("❌ [Web Server] Connection error while serving client: {}", e);
    }
}

async fn dynamic_handler(State(state): State<AppState>, req: Request) -> Response {
    let method = req.method().clone();
    let mut path = req.uri().path().to_string();
    tracing::info!("📥 [Web Server] Received {} request for path: {}", method, path);
    
    let host = req.headers().get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host())
        .unwrap_or("");
    let host_domain = host.split(':').next().unwrap_or(host);
    tracing::debug!("🌐 [Web Server] Extracted Host: {}", host_domain);

    let mut matched_routes: Vec<&crate::config::WebServerConfig> = state.routes.iter()
        .filter(|r| r.domain == host_domain)
        .collect();
    
    if matched_routes.is_empty() {
        matched_routes = state.routes.iter()
            .filter(|r| host_domain.ends_with(&format!(".{}", r.domain)))
            .collect();
            
    }

    let mut matched_route = None;
    for route in &matched_routes {
        if route.path == "/" || route.path == "*" || route.path == "/*" {
            matched_route = Some(*route);
            break;
        } else if path == route.path || path.starts_with(&format!("{}/", route.path.trim_end_matches('/'))) {
            matched_route = Some(*route);
            break;
        }
    }

    let mut req = req;

    let route = match matched_route {
        Some(r) => {
            tracing::info!("✅ [Web Server] Path {} matched route configuration of type '{}'", path, r.r#type);
            r
        },
        None => {
            tracing::info!("🔄 [Web Server] Path {} did not match any route. Falling back to panel_ui.", path);
            let exe_dir = std::env::current_exe().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default()).parent().unwrap_or(std::path::Path::new("")).to_path_buf();
            let ui_dir = exe_dir.join("panel_ui/dist");
            let req_path = path.trim_start_matches('/');
            let file_path = ui_dir.join(req_path);
            
            if file_path.exists() && file_path.is_file() {
                let content_type = mime_guess::from_path(&file_path).first_or_octet_stream();
                if let Ok(content) = tokio::fs::read(&file_path).await {
                    return axum::response::Response::builder()
                        .header("Content-Type", content_type.as_ref())
                        .body(axum::body::Body::from(content))
                        .unwrap();
                }
            }
            
            let index_file = ui_dir.join("index.html");
            if let Ok(content) = tokio::fs::read(&index_file).await {
                return axum::response::Response::builder()
                    .header("Content-Type", "text/html")
                    .body(axum::body::Body::from(content))
                    .unwrap();
            }
            
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    if route.block_hidden_files.unwrap_or(true) {
        let file_name = path.split('/').last().unwrap_or("");
        if file_name.starts_with('.') {
            tracing::warn!("❌ [Web Server] Blocked access to hidden file: {}", path);
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }

    let new_path_opt = if let Some(rewrites) = &route.rewrites {
        rewrites.get(&path).cloned()
    } else {
        None
    }.or_else(|| route.extra.get(&path).cloned());

    if let Some(new_path) = new_path_opt {
        tracing::info!("🔄 [Web Server] Rewriting path from {} to {}", path, new_path);
        let mut parts = req.uri().clone().into_parts();
        let pq = match parts.path_and_query {
            Some(ref old_pq) => {
                let mut pq_str = new_path.clone();
                if let Some(q) = old_pq.query() {
                    pq_str.push('?');
                    pq_str.push_str(q);
                }
                axum::http::uri::PathAndQuery::try_from(pq_str.as_str()).unwrap_or_else(|_| axum::http::uri::PathAndQuery::from_static("/"))
            }
            None => axum::http::uri::PathAndQuery::try_from(new_path.as_str()).unwrap_or_else(|_| axum::http::uri::PathAndQuery::from_static("/")),
        };
        parts.path_and_query = Some(pq);
        if let Ok(new_uri) = axum::http::Uri::from_parts(parts) {
            *req.uri_mut() = new_uri;
        }
        path = new_path;
    }

    match route.r#type.as_str() {
        "static" => {
            let root_str = route.root.clone().unwrap_or_else(|| "./".to_string());
            let root_path = std::path::Path::new(&root_str);
            let absolute_root = if root_path.is_absolute() {
                root_path.to_path_buf()
            } else {
                let exe_dir = std::env::current_exe()
                    .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
                    .parent()
                    .unwrap_or(std::path::Path::new(""))
                    .to_path_buf();
                exe_dir.join(root_path)
            };
            
            let index_file = absolute_root.join("index.html");
            
            let serve_dir = ServeDir::new(&absolute_root)
                .fallback(tower_http::services::ServeFile::new(index_file))
                .precompressed_gzip()
                .precompressed_br();
                
            match serve_dir.oneshot(req).await {
                Ok(res) => res.into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Static file error").into_response(),
            }
        }
        "reverse_proxy" => {
            let target = route.target.clone().unwrap_or_default();
            tracing::info!("🔄 [Reverse Proxy] Forwarding request {} to target: {}", path, target);
            let target_trim = target.trim_end_matches('/');
            
            let host_header = req.headers().get(axum::http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .or_else(|| req.uri().host())
                .unwrap_or("")
                .to_string();
            let client_ip_str = state.client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "127.0.0.1".to_string());

            let mut is_unix = false;
            let mut socket_path = "".to_string();
            
            if let Some(stripped) = target_trim.strip_prefix("unix://") {
                is_unix = true;
                socket_path = stripped.to_string();
            } else if let Some(stripped) = target_trim.strip_prefix("unix:/") {
                is_unix = true;
                socket_path = stripped.to_string();
            } else if let Some(stripped) = target_trim.strip_prefix("unix//") {
                is_unix = true;
                socket_path = stripped.to_string();
            }
            
            if is_unix {
                if !socket_path.starts_with('/') {
                    socket_path = format!("/{}", socket_path);
                }
                return match handle_unix_reverse_proxy(&socket_path, req, &client_ip_str, &host_header, route).await {
                    Ok(res) => res,
                    Err(e) => (StatusCode::BAD_GATEWAY, format!("Unix Gateway Error: {}", e)).into_response(),
                };
            }

            let pq = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
            let url = if target_trim.starts_with("http://") || target_trim.starts_with("https://") {
                format!("{}{}", target_trim, pq)
            } else {
                format!("http://{}{}", target_trim, pq)
            };
            
            let mut builder = state.client.request(req.method().clone(), &url);
            
            for (k, v) in req.headers() {
                builder = builder.header(k.clone(), v.clone());
            }

            builder = builder.header("X-Real-IP", &client_ip_str);
            builder = builder.header("X-Forwarded-For", &client_ip_str);
            builder = builder.header("X-Forwarded-Host", &host_header);
            builder = builder.header("X-Forwarded-Server", &host_header);
            builder = builder.header("X-Forwarded-Proto", "https");

            for (k, v) in &route.extra {
                let mut v_replaced = v.clone();
                if v_replaced.contains("{client_ip}") {
                    v_replaced = v_replaced.replace("{client_ip}", &client_ip_str);
                }
                if v_replaced.contains("{host}") {
                    v_replaced = v_replaced.replace("{host}", &host_header);
                }
                builder = builder.header(k, v_replaced);
            }

            let body_stream = req.into_body();
            // reqwest expects a stream of Bytes, not a stream of Frame<Bytes>
            use futures::StreamExt;
            let byte_stream = http_body_util::BodyStream::new(body_stream)
                .filter_map(|frame_res| async {
                    match frame_res {
                        Ok(frame) => {
                            if let Ok(bytes) = frame.into_data() {
                                Some(Ok::<_, std::io::Error>(bytes))
                            } else {
                                None // Ignore trailers for simplicity
                            }
                        }
                        Err(e) => Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
                    }
                });
            let reqwest_body = reqwest::Body::wrap_stream(byte_stream);
            builder = builder.body(reqwest_body);

            match builder.send().await {
                Ok(resp) => {
                    tracing::info!("✅ [Reverse Proxy] Successfully received response from target (Status: {})", resp.status());
                    let mut res_builder = axum::response::Response::builder().status(resp.status());
                    for (k, v) in resp.headers() {
                        res_builder = res_builder.header(k.clone(), v.clone());
                    }
                    let stream = resp.bytes_stream();
                    let body = axum::body::Body::from_stream(stream);
                    res_builder.body(body).unwrap()
                }
                Err(e) => {
                    tracing::error!("❌ [Reverse Proxy] Gateway Error! Failed to forward request to {}: {}", url, e);
                    (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
                }
            }
        }
        "fastcgi" => {
            let target = route.target.clone().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let current_path = req.uri().path();
            if !current_path.ends_with(".php") && !current_path.ends_with('/') {
                let root = route.root.clone().unwrap_or_else(|| "./".to_string());
                let serve_dir = tower_http::services::ServeDir::new(root).precompressed_gzip().precompressed_br();
                use tower::ServiceExt;
                match serve_dir.oneshot(req).await {
                    Ok(res) => res.into_response(),
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Static file error").into_response(),
                }
            } else {
                match handle_fastcgi(&target, &route, req).await {
                    Ok(res) => res,
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("FastCGI Error: {}", e)).into_response(),
                }
            }
        }
        _ => (StatusCode::BAD_REQUEST, "Unknown route type").into_response(),
    }
}

async fn handle_fastcgi(target: &str, route: &WebServerConfig, req: Request) -> Result<Response, String> {
    use fastcgi_client::{Client, Params, Request as FcgiRequest};
    
    let (parts, body) = req.into_parts();
    
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b.to_vec(),
        Err(_) => vec![],
    };

    let doc_root = route.root.clone().unwrap_or_else(|| "/var/www/html".to_string());
    
    let script_name = parts.uri.path().to_string();
    let script_filename = format!("{}{}", doc_root, script_name);

    let mut extras = Params::default()
        .document_root(doc_root)
        .script_name(script_name.clone())
        .script_filename(script_filename)
        .document_uri(script_name)
        .remote_addr("127.0.0.1")
        .remote_port(0)
        .server_addr("127.0.0.1")
        .server_port(80)
        .server_name("localhost");

    for (k, v) in &route.extra {
        extras = extras.custom(k.clone(), v.clone());
    }

    let http_request = axum::http::Request::from_parts(parts, fastcgi_client::io::Cursor::new(body_bytes));
    
    let fcgi_req = FcgiRequest::try_from_http_with(http_request, extras)
        .map_err(|e| e.to_string())?;

    let mut is_unix = false;
    let mut socket_path = "".to_string();
    
    if let Some(stripped) = target.strip_prefix("unix://") {
        is_unix = true;
        socket_path = stripped.to_string();
    } else if let Some(stripped) = target.strip_prefix("unix:/") {
        is_unix = true;
        socket_path = stripped.to_string();
    } else if let Some(stripped) = target.strip_prefix("unix//") {
        is_unix = true;
        socket_path = stripped.to_string();
    }

    if is_unix {
        if !socket_path.starts_with('/') {
            socket_path = format!("/{}", socket_path);
        }
        let stream = tokio::net::UnixStream::connect(&socket_path).await.map_err(|e| format!("FastCGI Unix Connect Error: {}", e))?;
        let client = Client::new_tokio(stream);
        let response = client.execute_once(fcgi_req).await.map_err(|e| e.to_string())?;
        let http_response: axum::http::Response<Vec<u8>> = response.try_into().map_err(|e| format!("{:?}", e))?;
        let (parts, body) = http_response.into_parts();
        Ok(axum::http::Response::from_parts(parts, axum::body::Body::from(body)))
    } else {
        let stream = tokio::net::TcpStream::connect(target).await.map_err(|e| format!("FastCGI TCP Connect Error: {}", e))?;
        let client = Client::new_tokio(stream);
        let response = client.execute_once(fcgi_req).await.map_err(|e| e.to_string())?;
        let http_response: axum::http::Response<Vec<u8>> = response.try_into().map_err(|e| format!("{:?}", e))?;
        let (parts, body) = http_response.into_parts();
        Ok(axum::http::Response::from_parts(parts, axum::body::Body::from(body)))
    }
}

async fn handle_unix_reverse_proxy(socket_path: &str, req: Request, client_ip_str: &str, host_header: &str, route: &WebServerConfig) -> Result<Response, String> {
    use tokio::net::UnixStream;
    use hyper_util::rt::TokioIo;
    use axum::body::Body;

    tracing::debug!("🔌 [Unix Proxy] Attempting to connect to unix socket: {}", socket_path);
    let stream = match tokio::time::timeout(std::time::Duration::from_secs(5), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => {
            tracing::debug!("🔌 [Unix Proxy] Successfully connected to unix socket: {}", socket_path);
            s
        },
        Ok(Err(e)) => return Err(format!("Failed to connect to unix socket: {}", e)),
        Err(_) => return Err("Timeout connecting to unix socket".to_string()),
    };
    
    let io = TokioIo::new(stream);
    
    tracing::debug!("🔌 [Unix Proxy] Performing HTTP/1.1 handshake on unix socket...");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| format!("Unix handshake error: {}", e))?;
    tracing::debug!("🔌 [Unix Proxy] HTTP/1.1 handshake successful.");
    
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::error!("❌ [Unix Proxy] Connection error: {}", err);
        }
    });

    let (mut parts, body) = req.into_parts();
    
    let pq = parts.uri.path_and_query().map(|x| x.as_str()).unwrap_or("/").to_string();
    parts.uri = axum::http::Uri::builder()
        .path_and_query(pq)
        .build()
        .unwrap_or_else(|_| parts.uri);

    parts.headers.insert("X-Real-IP", axum::http::HeaderValue::from_str(client_ip_str).unwrap());
    parts.headers.insert("X-Forwarded-For", axum::http::HeaderValue::from_str(client_ip_str).unwrap());
    parts.headers.insert("X-Forwarded-Proto", axum::http::HeaderValue::from_str("https").unwrap());
    if let Ok(hv) = axum::http::HeaderValue::from_str(host_header) {
        parts.headers.insert("X-Forwarded-Host", hv.clone());
        parts.headers.insert("X-Forwarded-Server", hv.clone());
        parts.headers.insert(axum::http::header::HOST, hv);
    }
    
    for (k, v) in &route.extra {
        let mut v_replaced = v.clone();
        if v_replaced.contains("{client_ip}") {
            v_replaced = v_replaced.replace("{client_ip}", client_ip_str);
        }
        if v_replaced.contains("{host}") {
            v_replaced = v_replaced.replace("{host}", host_header);
        }
        if let (Ok(hn), Ok(hv)) = (axum::http::header::HeaderName::try_from(k.as_str()), axum::http::HeaderValue::from_str(&v_replaced)) {
            parts.headers.insert(hn, hv);
        }
    }

    let req = axum::http::Request::from_parts(parts, body);

    tracing::debug!("📨 [Unix Proxy] Sending request to unix socket backend...");
    let res = match tokio::time::timeout(std::time::Duration::from_secs(30), sender.send_request(req)).await {
        Ok(Ok(r)) => {
            tracing::info!("✅ [Unix Proxy] Received response from backend (Status: {})", r.status());
            r
        },
        Ok(Err(e)) => return Err(format!("Unix request error: {}", e)),
        Err(_) => return Err("Timeout waiting for response from unix socket backend".to_string()),
    };
    
    let (res_parts, res_body) = res.into_parts();
    let body = Body::new(res_body);
    
    Ok(axum::http::Response::from_parts(res_parts, body))
}

