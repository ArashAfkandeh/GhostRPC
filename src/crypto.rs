use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// ==========================================
// 2. CRYPTO (بخشی از "2. TCP KEEPALIVE & CRYPTO")
// ==========================================

pub fn derive_cipher(secret: &str) -> Aes256Gcm {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let key: Key<aes_gcm::aes::Aes256> = *Key::<aes_gcm::aes::Aes256>::from_slice(&hasher.finalize());
    Aes256Gcm::new(&key)
}

pub fn encrypt_payload(cipher: &Aes256Gcm, data: &[u8]) -> Bytes {
    let normal = Normal::new(128.0, 64.0).unwrap();
    let pad_len = (normal.sample(&mut rand::thread_rng()) as i32).clamp(16, 512) as u16;

    let mut padding = vec![0u8; pad_len as usize];
    rand::thread_rng().fill(&mut padding[..]);

    let mut plaintext = Vec::with_capacity(2 + padding.len() + data.len());
    plaintext.extend_from_slice(&pad_len.to_be_bytes());
    plaintext.extend_from_slice(&padding);
    plaintext.extend_from_slice(data);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    let mut final_payload = BytesMut::with_capacity(12 + ciphertext.len());
    final_payload.extend_from_slice(&nonce);
    final_payload.extend_from_slice(&ciphertext);
    final_payload.freeze()
}

pub fn decrypt_payload(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 12 { return Err("Payload too short"); }
    let (nonce, ciphertext) = data.split_at(12);

    let plaintext = cipher.decrypt(nonce.into(), ciphertext).map_err(|_| "Decryption failed")?;
    if plaintext.len() < 2 { return Err("Plaintext too short"); }

    let pad_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if plaintext.len() < 2 + pad_len { return Err("Invalid padding"); }

    Ok(plaintext[2 + pad_len..].to_vec())
}

// ==========================================
// 5. REALITY-STYLE CAMOUFLAGE AUTHENTICATION
// ------------------------------------------
// به جای اتکا به فیلدهای داخلی و غیرمستند TLS (که پیاده‌سازی صددرصد وفادار
// به آن نیازمند Fork کردن یک کتابخانه TLS است)، هویت کلاینت واقعی از طریق
// یک برچسب (Label) مشتق‌شده با HMAC-SHA256 که در ابتدای مقدار SNI درج
// می‌شود احراز می‌گردد. این برچسب هر AUTH_WINDOW_SECS ثانیه یکبار چرخش
// (Rotate) می‌کند تا در برابر Replay ساده مقاوم باشد و از دید یک اسکنر
// غیرفعال/فعال، دقیقاً شبیه یک ساب‌دامین معمولی CDN/Edge به نظر برسد.
// این مقدار هرگز روی سیم به صورت رمزنگاری‌شده نیست (SNI همیشه Plaintext
// است) اما بدون دانستن `secret` قابل جعل یا حدس زدن نیست.
// ==========================================

/// طول عمر هر پنجره‌ی چرخشی احراز هویت (به ثانیه).
pub const AUTH_WINDOW_SECS: u64 = 30;

fn current_window() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    now / AUTH_WINDOW_SECS
}

/// محاسبه‌ی برچسب هگزادسیمال ۱۶ کاراکتری برای یک پنجره‌ی زمانی مشخص.
pub fn compute_camouflage_label(secret: &str, window: u64) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"stealth-tunnel-reality-v1");
    mac.update(&window.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

/// (سمت کلاینت) ساخت مقدار SNI پوششی برای بازه‌ی زمانی جاری.
pub fn build_camouflage_sni(secret: &str, camouflage_domain: &str) -> String {
    format!("{}.{}", compute_camouflage_label(secret, current_window()), camouflage_domain)
}

/// (سمت سرور) بررسی این‌که آیا SNI دریافتی متعلق به یک کلاینت اصیل ماست یا نه.
/// سه پنجره (قبلی/جاری/بعدی) برای تحمل اختلاف ساعت (Clock Skew) شبکه بررسی می‌شود.
pub fn is_authorized_sni(sni: &str, secret: &str, camouflage_domain: &str) -> bool {
    let now_window = current_window();
    for w in [now_window.saturating_sub(1), now_window, now_window + 1] {
        if sni == format!("{}.{}", compute_camouflage_label(secret, w), camouflage_domain) {
            return true;
        }
    }
    false
}
