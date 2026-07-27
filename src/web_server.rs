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

    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, hyper_service)
        .await;
}

async fn dynamic_handler(State(state): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    
    let mut matched_route = None;
    for route in &state.routes {
        if route.path == "/" || route.path == "*" || route.path == "/*" {
            matched_route = Some(route);
            break;
        } else if path == route.path || path.starts_with(&format!("{}/", route.path.trim_end_matches('/'))) {
            matched_route = Some(route);
            break;
        }
    }

    let route = match matched_route {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "Not Found").into_response(),
    };

    match route.r#type.as_str() {
        "static" => {
            let root = route.root.clone().unwrap_or_else(|| "./".to_string());
            let serve_dir = ServeDir::new(root).precompressed_gzip().precompressed_br();
            match serve_dir.oneshot(req).await {
                Ok(res) => res.into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Static file error").into_response(),
            }
        }
        "reverse_proxy" => {
            let target = route.target.clone().unwrap_or_default();
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
                    let mut res_builder = axum::response::Response::builder().status(resp.status());
                    for (k, v) in resp.headers() {
                        res_builder = res_builder.header(k.clone(), v.clone());
                    }
                    let stream = resp.bytes_stream();
                    let body = axum::body::Body::from_stream(stream);
                    res_builder.body(body).unwrap()
                }
                Err(_) => (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response(),
            }
        }
        "fastcgi" => {
            let target = route.target.clone().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            match handle_fastcgi(&target, &route, req).await {
                Ok(res) => res,
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("FastCGI Error: {}", e)).into_response(),
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

    let stream = UnixStream::connect(socket_path).await.map_err(|e| format!("Failed to connect to unix socket: {}", e))?;
    let io = TokioIo::new(stream);
    
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| format!("Unix handshake error: {}", e))?;
    
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            let _ = err;
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

    let res = sender.send_request(req).await.map_err(|e| format!("Unix request error: {}", e))?;
    
    let (res_parts, res_body) = res.into_parts();
    let body = Body::new(res_body);
    
    Ok(axum::http::Response::from_parts(res_parts, body))
}
