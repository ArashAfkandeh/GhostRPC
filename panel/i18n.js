/* GhostRPC panel — language (fa default, RTL / en), theme and icons. Loaded in <head> to avoid flashes. */
(function () {
  'use strict';

  var FA = {
    switch_lang: 'English', switch_theme: 'تغییر پوسته', login_sub: 'ورود به پنل مدیریت',
    username: 'نام کاربری', password: 'رمز عبور', show_password: 'نمایش رمز', hide_password: 'پنهان کردن رمز',
    sign_in: 'ورود', signing_in: 'در حال ورود…', sign_out: 'خروج',

    err_invalid_credentials: 'نام کاربری یا رمز عبور درست نیست.',
    err_locked: 'تلاش‌های ناموفق زیاد بود. {n} دقیقه‌ی دیگر دوباره امتحان کنید.',
    err_network: 'ارتباط با سرویس برقرار نشد.',
    err_bad_request: 'درخواست نامعتبر است.',
    err_unauthorized: 'نشست شما پایان یافته است. دوباره وارد شوید.',
    err_csrf: 'نشست نامعتبر است. صفحه را دوباره بارگذاری کنید.',
    err_read_only: 'پنل در حالت فقط‌خواندنی است.',
    err_scanner_unavailable: 'اسکنر آی‌پی Direct در حال اجرا نیست؛ پاک‌سازی و اسکن دوباره ممکن نیست.',
    err_clean_ip_clear_failed: 'پاک‌کردن کش آی‌پی‌های تمیز ناموفق بود. فایل کش را بررسی کنید و دوباره تلاش کنید.',
    err_conflict: 'فایل پیکربندی در این فاصله تغییر کرده است.',
    err_invalid_config: 'پیکربندی معتبر نیست.',
    err_wrong_password: 'رمز فعلی درست نیست.',
    err_password_too_short: 'رمز جدید باید دست‌کم ۱۰ نویسه باشد.',
    err_password_same: 'رمز جدید باید با رمز فعلی فرق داشته باشد.',
    err_save_failed: 'ذخیره‌ی اطلاعات ناموفق بود.',
    err_write_failed: 'نوشتن فایل پیکربندی ناموفق بود.',
    err_read_failed: 'خواندن فایل پیکربندی ناموفق بود.',
    err_bad_backup_name: 'نام نسخه‌ی پشتیبان نامعتبر است.',
    err_backup_not_found: 'نسخه‌ی پشتیبان پیدا نشد.',
    err_hash_failed: 'پردازش رمز ناموفق بود.',
    err_generic: 'خطای ناشناخته: {c}',
    err_repo_stats_unavailable: 'دریافت تعداد ستاره‌های GitHub ممکن نشد.',
    err_repo_stats_invalid: 'پاسخ تعداد ستاره‌های GitHub معتبر نیست.',

    nav_dashboard: 'داشبورد', nav_tunnels: 'تونل‌ها', nav_connections: 'اتصال‌های فعال', nav_logs: 'گزارش‌ها',
    nav_config: 'تنظیمات', nav_certs: 'گواهی‌ها', nav_account: 'حساب کاربری',
    github_project: 'پروژه‌ی GitHub', repo_stars: '{n} ستاره', repo_stars_unavailable: 'نامشخص',
    role_server: 'سرور', role_client: 'کلاینت', role_unknown: '—',

    change_pw_banner: 'رمز فعلی را شما انتخاب نکرده‌اید. برای امنیت بیشتر همین حالا آن را عوض کنید.',
    change_password: 'تغییر رمز عبور', offline_banner: 'ارتباط با GhostRPC قطع شده است؛ در حال تلاش مجدد…',
    online: 'متصل', offline_short: 'قطع',

    tx: 'ارسال به تونل', rx: 'دریافت از تونل', total: 'مجموع', range_15m: '۱۵ دقیقه', range_24h: '۲۴ ساعت',
    state: 'وضعیت', active_streams: 'استریم‌های فعال', since_start: 'از آغاز اجرا', tunnel_sessions: 'نشست‌های تونل',
    rejected: 'درخواست‌های ردشده', rejected_sub: 'درخواست H2 به مسیر مخفی با secret نامعتبر یا هدر ناقص؛ از شروع اجرا',
    route: 'مسیر ترافیک', summary: 'خلاصه‌ی پیکربندی', system: 'منابع سیستم', recent_events: 'رویدادهای اخیر', all_logs: 'همه‌ی گزارش‌ها',

    st_running: 'در حال اجرا', st_starting: 'در حال راه‌اندازی', st_direct: 'مسیر مستقیم', st_reverse: 'مسیر Reverse', st_unavailable: 'تونل برقرار نیست',
    st_sub_server: 'سرور پذیرای اتصال‌هاست', st_sub_direct: 'کلاینت مستقیم به سرور وصل است', st_sub_reverse: 'سرور از طریق Reverse به کلاینت وصل است',
    st_sub_unavailable: 'هیچ مسیر آماده‌ای وجود ندارد', st_sub_starting: 'در حال بررسی مسیرها', st_sub_unknown: 'نقش مشخص نیست',

    route_streams: 'استریم', route_tunnels: 'تونل', route_users: 'کاربران', route_this_client: 'این کلاینت', route_remote_server: 'سرور', route_targets: 'مقصدها',
    route_remote_client: 'کلاینت', route_this_server: 'این سرور', tag_direct: 'Direct', tag_reverse: 'Reverse', tag_tunnel: 'تونل',

    sum_listen: 'آدرس شنود', sum_protocols: 'پروتکل‌ها', sum_tunnel_sni: 'دامنه‌های تونل', sum_camouflage: 'استتار', sum_secret: 'رمز تونل',
    sum_acme: 'گواهی خودکار', sum_web: 'وب‌سرور داخلی', sum_sni_proxy: 'SNI Proxy', sum_dialers: 'Reverse خروجی', sum_remotes: 'مقصدهای دوردست',
    sum_pool: 'اتصال به‌ازای هر نود', sum_reverse_bind: 'شنود Reverse', sum_scanner: 'اسکنر آی‌پی', sum_hidden: 'مسیر مخفی',
    secret_set: 'تنظیم شده', secret_unset: 'تنظیم نشده', yes: 'بله', no: 'خیر', none: 'ندارد', on: 'فعال', off: 'غیرفعال', routes_n: '{n} مسیر',

    sys_host: 'میزبان', sys_cpu: 'پردازنده', sys_load: 'بار سیستم', sys_memory: 'حافظه‌ی سیستم', sys_process: 'حافظه‌ی GhostRPC',
    sys_threads: 'رشته‌ها', sys_fds: 'فایل‌های باز', cores: '{n} هسته',

    protocol_order: 'اولویت پروتکل‌ها',
    protocol_hint: 'پروتکل اول ترجیح داده می‌شود و اگر وصل نشد یا ترافیک را عبور نداد، خودکار به بعدی می‌رود. ترتیب را در بخش تنظیمات (protocols) عوض کنید.',
    current_tunnel_type: 'نوع تونل فعلی', tunnel_path_direct: 'Direct', tunnel_path_reverse: 'Reverse', tunnel_path_unavailable: 'متصل نیست',
    direct_tunnel: 'تونل Direct', location: 'لوکیشن', pool: 'استخر اتصال', latency: 'تأخیر', no_nodes: 'تونل Direct تعریف نشده است.',
    reverse_title: 'تونل Reverse', clean_ips: 'آی‌پی‌های تمیز', sessions_title: 'نشست‌های تونل',
    protocol: 'پروتکل', direction: 'جهت', kind: 'نوع', peer: 'همتا', age: 'مدت', dead_targets: 'مقصدهای مسدودشده (Circuit Breaker)',
    clear_dead: 'پاک‌سازی', dead_hint: 'مقصدهایی که اتصال به آن‌ها شکست خورده موقتاً کنار گذاشته می‌شوند تا ترافیک بی‌دلیل هدر نرود.',
    dir_in: 'ورودی', dir_out: 'خروجی', kind_direct: 'Direct', kind_reverse: 'Reverse', kind_user: 'کاربر', kind_tunnel: 'تونل',
    no_sessions: 'نشست فعالی وجود ندارد.', no_dead: 'مقصد مسدودی وجود ندارد.', dead_cleared: '{n} مقصد آزاد شد.',
    reverse_disabled: 'Reverse غیرفعال است.', reverse_bind: 'شنود روی', reverse_ready: 'آماده', reverse_waiting: 'در انتظار اتصال سرور',
    group_unlabeled: 'بدون لوکیشن', parked: 'استریم آماده', ws_sessions: 'نشست WssMux',
    ip_count: '{n} آی‌پی', show_ips: 'نمایش فهرست', no_ips: 'هنوز آی‌پی تمیزی پیدا نشده است.',
    rescan_clean_ips: 'اسکن دوباره', clean_ips_scan_unavailable: 'اسکنر Direct فعال نیست.',
    confirm_clean_ips_title: 'پاک‌کردن آی‌پی‌های تمیز؟', confirm_clean_ips_text: 'کش حافظه و فایل پاک می‌شود و اسکنر فوراً برای پیدا کردن آی‌پی‌های تازه بیدار خواهد شد. اتصال‌های فعال قطع نمی‌شوند.',
    clean_ips_scan_requested: 'کش پاک شد ({n} آی‌پی). درخواست اسکن جدید ارسال شد.',
    cooling: 'در استراحت', healthy: 'سالم', degraded: 'ناقص', offline: 'قطع',
    legend_h2: 'HTTP/2', legend_ws: 'WssMux', legend_down: 'قطع',
    server_accepts: 'پروتکل‌های پذیرفته‌شده', dialers_title: 'تونل‌های Reverse خروجی',
    no_dialers: 'تونل Reverse تعریف نشده است.',
    no_reverse_groups: 'هنوز اطلاعاتی از تونل‌های Reverse دریافت نشده است.',
    active_tunnels: 'اتصال فعال',

    filter_ph: 'فیلتر…', open_streams: 'استریم باز', source: 'مبدأ', target: 'مقصد',
    conn_note: 'نمایش {n} مورد از جدیدترین استریم‌ها.',
    pause: 'توقف', resume: 'ادامه', clear_view: 'پاک کردن نمایش', download: 'دانلود', no_logs: 'گزارشی برای نمایش نیست.',

    config_file: 'فایل پیکربندی', config_guide: 'راهنمای پیکربندی', config_guide_client: 'نمونه کلاینت', config_guide_server: 'نمونه سرور',
    config_guide_hint: 'این نمونه‌ها همراه باینری ساخته شده‌اند و پیکربندی فعال شما نیستند. مقادیر نمونه و توکن‌ها را پیش از استفاده جایگزین کنید.',
    config_guide_loading: 'در حال بارگذاری نمونه…', close: 'بستن',
    validate: 'بررسی صحت', save_apply: 'ذخیره و اعمال', revert: 'بازگردانی تغییرات',
    download_toml: 'دانلود فایل TOML',
    reload_now: 'بارگذاری مجدد تنظیمات', read_only_note: 'پنل در حالت فقط‌خواندنی است؛ ویرایش و اجرای عملیات غیرفعال است.',
    conflict_note: 'فایل در این فاصله روی دیسک تغییر کرده است. برای جلوگیری از بازنویسی، ابتدا آخرین نسخه را بارگذاری کنید.',
    load_latest: 'بارگذاری آخرین نسخه', backups: 'نسخه‌های پشتیبان',
    backups_hint: 'پیش از هر ذخیره، نسخه‌ی قبلی خودکار نگه داشته می‌شود (۱۵ نسخه‌ی آخر).',
    restore: 'بازیابی', no_backups: 'هنوز نسخه‌ی پشتیبانی وجود ندارد.', unsaved: 'تغییرات ذخیره‌نشده', saved_state: 'ذخیره‌شده',
    last_modified: 'آخرین تغییر', line_col: 'سطر {l}، ستون {c}',
    valid_ok: 'پیکربندی معتبر است.', saved_ok: 'ذخیره شد. تغییرات طی چند ثانیه بدون قطع اتصال‌ها اعمال می‌شود.',
    restored_ok: 'نسخه‌ی پشتیبان بازیابی شد و به‌زودی اعمال می‌شود.', reload_requested: 'درخواست بارگذاری مجدد ارسال شد.',
    confirm_save_title: 'ذخیره و اعمال تنظیمات؟', confirm_save_text: 'پیکربندی جدید با Hot-Reload اعمال می‌شود. اتصال‌های جاری قطع نمی‌شوند.',
    confirm_restore_title: 'بازیابی این نسخه؟', confirm_restore_text: 'پیکربندی فعلی جایگزین می‌شود (از آن هم نسخه‌ی پشتیبان گرفته می‌شود).',
    confirm_reload_title: 'بارگذاری مجدد؟', confirm_reload_text: 'شنودها با همان تنظیمات دوباره راه‌اندازی می‌شوند؛ اتصال‌های جاری ادامه می‌یابند.',
    confirm_clear_title: 'پاک‌سازی مقصدهای مسدود؟', confirm_clear_text: 'همه‌ی مقصدها دوباره امتحان می‌شوند.',
    confirm_revoke_title: 'خروج این نشست؟', confirm_revoke_text: 'دستگاه مربوط باید دوباره وارد شود.',
    cancel: 'انصراف', confirm: 'تأیید',
    warn_both_roles: 'هم [server] و هم [client] تعریف شده است؛ فقط [server] اجرا می‌شود.',
    warn_admin_removed: 'بخش [admin] حذف شده است؛ پس از اعمال، پنل از دسترس خارج می‌شود.',
    warn_admin_disabled: 'پنل در این پیکربندی غیرفعال شده است؛ پس از اعمال، از دسترس خارج می‌شود.',
    warn_admin_bind_changed: 'آدرس شنود پنل تغییر کرده است؛ پس از اعمال باید از آدرس جدید وارد شوید.',
    warn_admin_proxy_changed: 'تنظیم trust_proxy تغییر کرده است.',
    warn_admin_weak_password: 'رمز پنل در بخش [admin] کوتاه‌تر از ۱۰ نویسه است.',

    zone: 'زون', issued: 'صدور', expires: 'انقضا', remaining: 'باقی‌مانده', no_certs: 'گواهی‌ای در پوشه‌ی certs پیدا نشد.',
    certs_hint: 'تاریخ‌ها از خودِ گواهی خوانده می‌شود. تمدید خودکار با توکن Cloudflare یا ArvanCloud انجام می‌شود.',
    cert_valid: 'معتبر', cert_soon: 'نزدیک انقضا', cert_expired: 'منقضی', cert_renew: 'تمدید در نوبت', days_n: '{n} روز',

    current_password: 'رمز فعلی', new_password: 'رمز جدید', repeat_password: 'تکرار رمز جدید', password_rule: 'دست‌کم ۱۰ نویسه',
    save_password: 'ذخیره‌ی رمز', passwords_mismatch: 'رمز جدید و تکرار آن یکسان نیست.',
    password_changed: 'رمز تغییر کرد. نشست‌های دیگر بسته شدند.',
    password_changed_relogin: 'رمز در بخش [admin] فایل پیکربندی ذخیره شد. پنل با تنظیم جدید راه‌اندازی می‌شود؛ دوباره وارد شوید…',
    active_sessions: 'نشست‌های فعال', sessions_hint: 'دستگاه‌هایی که الان با این حساب وارد پنل شده‌اند.',
    this_session: 'این نشست', revoke: 'خروج', last_active: 'آخرین فعالیت',

    ago: 'پیش', now: 'هم‌اکنون', copy: 'کپی', copied: 'کپی شد', loading: 'در حال بارگذاری…',
    ok_done: 'انجام شد'
  };

  var EN = {
    switch_lang: 'فارسی', switch_theme: 'Switch theme', login_sub: 'Sign in to the admin panel',
    username: 'Username', password: 'Password', show_password: 'Show password', hide_password: 'Hide password',
    sign_in: 'Sign in', signing_in: 'Signing in…', sign_out: 'Sign out',

    err_invalid_credentials: 'Wrong username or password.',
    err_locked: 'Too many failed attempts. Try again in {n} minute(s).',
    err_network: 'Could not reach the service.',
    err_bad_request: 'Invalid request.',
    err_unauthorized: 'Your session has ended. Sign in again.',
    err_csrf: 'Invalid session. Reload the page.',
    err_read_only: 'The panel is read-only.',
    err_scanner_unavailable: 'The Direct IP scanner is not running, so the cache cannot be cleared and rescanned.',
    err_clean_ip_clear_failed: 'Could not clear the clean-IP cache. Check the cache file and try again.',
    err_conflict: 'The config file changed in the meantime.',
    err_invalid_config: 'The configuration is not valid.',
    err_wrong_password: 'The current password is wrong.',
    err_password_too_short: 'The new password needs at least 10 characters.',
    err_password_same: 'The new password must differ from the current one.',
    err_save_failed: 'Could not save the data.',
    err_write_failed: 'Could not write the config file.',
    err_read_failed: 'Could not read the config file.',
    err_bad_backup_name: 'Invalid backup name.',
    err_backup_not_found: 'Backup not found.',
    err_hash_failed: 'Could not process the password.',
    err_generic: 'Unexpected error: {c}',
    err_repo_stats_unavailable: 'Could not load the GitHub star count.',
    err_repo_stats_invalid: 'GitHub returned an invalid star count.',

    nav_dashboard: 'Dashboard', nav_tunnels: 'Tunnels', nav_connections: 'Live connections', nav_logs: 'Logs',
    nav_config: 'Settings', nav_certs: 'Certificates', nav_account: 'Account',
    github_project: 'GhostRPC on GitHub', repo_stars: '{n} Star', repo_stars_unavailable: 'Unavailable',
    role_server: 'Server', role_client: 'Client', role_unknown: '—',

    change_pw_banner: 'You did not choose the current password. Change it now to keep the panel safe.',
    change_password: 'Change password', offline_banner: 'Lost the connection to GhostRPC; retrying…',
    online: 'Online', offline_short: 'Offline',

    tx: 'Sent into tunnel', rx: 'Received from tunnel', total: 'Total', range_15m: '15 min', range_24h: '24 h',
    state: 'Status', active_streams: 'Active streams', since_start: 'Since start', tunnel_sessions: 'Tunnel sessions',
    rejected: 'Rejected requests', rejected_sub: 'H2 requests to the hidden path with an invalid secret or incomplete headers; since startup',
    route: 'Traffic route', summary: 'Configuration summary', system: 'System resources', recent_events: 'Recent events', all_logs: 'All logs',

    st_running: 'Running', st_starting: 'Starting', st_direct: 'Direct path', st_reverse: 'Reverse path', st_unavailable: 'Tunnel down',
    st_sub_server: 'Server is accepting connections', st_sub_direct: 'Client is connected straight to the server', st_sub_reverse: 'Server is connected back through Reverse',
    st_sub_unavailable: 'No path is ready', st_sub_starting: 'Probing paths', st_sub_unknown: 'Role not known yet',

    route_streams: 'streams', route_tunnels: 'tunnels', route_users: 'Users', route_this_client: 'This client', route_remote_server: 'Server', route_targets: 'Targets',
    route_remote_client: 'Client', route_this_server: 'This server', tag_direct: 'Direct', tag_reverse: 'Reverse', tag_tunnel: 'Tunnel',

    sum_listen: 'Listen address', sum_protocols: 'Protocols', sum_tunnel_sni: 'Tunnel domains', sum_camouflage: 'Camouflage', sum_secret: 'Tunnel secret',
    sum_acme: 'Auto certificates', sum_web: 'Built-in web server', sum_sni_proxy: 'SNI proxy', sum_dialers: 'Outgoing Reverse', sum_remotes: 'Remote targets',
    sum_pool: 'Connections per node', sum_reverse_bind: 'Reverse listener', sum_scanner: 'IP scanner', sum_hidden: 'Hidden path',
    secret_set: 'Set', secret_unset: 'Not set', yes: 'Yes', no: 'No', none: 'None', on: 'On', off: 'Off', routes_n: '{n} route(s)',

    sys_host: 'Host', sys_cpu: 'CPU', sys_load: 'Load average', sys_memory: 'System memory', sys_process: 'GhostRPC memory',
    sys_threads: 'Threads', sys_fds: 'Open files', cores: '{n} cores',

    protocol_order: 'Protocol priority',
    protocol_hint: 'The first protocol is preferred. If it fails to connect or to carry traffic, the next one is used automatically. Change the order with protocols in Settings.',
    current_tunnel_type: 'Current tunnel type', tunnel_path_direct: 'Direct', tunnel_path_reverse: 'Reverse', tunnel_path_unavailable: 'Not connected',
    direct_tunnel: 'Direct Tunnel', location: 'Location', pool: 'Connection pool', latency: 'Latency', no_nodes: 'No Direct tunnel is configured.',
    reverse_title: 'Reverse tunnel', clean_ips: 'Clean IPs', sessions_title: 'Tunnel sessions',
    protocol: 'Protocol', direction: 'Direction', kind: 'Type', peer: 'Peer', age: 'Age', dead_targets: 'Blocked targets (circuit breaker)',
    clear_dead: 'Clear', dead_hint: 'Targets that failed to connect are set aside for a while so traffic is not wasted on them.',
    dir_in: 'Inbound', dir_out: 'Outbound', kind_direct: 'Direct', kind_reverse: 'Reverse', kind_user: 'User', kind_tunnel: 'Tunnel',
    no_sessions: 'No active sessions.', no_dead: 'No blocked targets.', dead_cleared: '{n} target(s) released.',
    reverse_disabled: 'Reverse is not enabled.', reverse_bind: 'Listening on', reverse_ready: 'Ready', reverse_waiting: 'Waiting for the server to connect',
    group_unlabeled: 'No location', parked: 'ready streams', ws_sessions: 'WssMux sessions',
    ip_count: '{n} IPs', show_ips: 'Show list', no_ips: 'No clean IP found yet.',
    rescan_clean_ips: 'Rescan IPs', clean_ips_scan_unavailable: 'The Direct scanner is not active.',
    confirm_clean_ips_title: 'Clear clean IPs?', confirm_clean_ips_text: 'The in-memory and file caches will be cleared, and the scanner will immediately look for fresh IPs. Active connections will not be interrupted.',
    clean_ips_scan_requested: 'Cache cleared ({n} IPs). A new scan was requested.',
    cooling: 'cooling down', healthy: 'Healthy', degraded: 'Degraded', offline: 'Down',
    legend_h2: 'HTTP/2', legend_ws: 'WssMux', legend_down: 'Down',
    server_accepts: 'Accepted protocols', dialers_title: 'Outgoing Reverse tunnels',
    no_dialers: 'No Reverse tunnel is configured.',
    no_reverse_groups: 'No Reverse tunnel information has been received yet.',
    active_tunnels: 'Active',

    filter_ph: 'Filter…', open_streams: 'Open streams', source: 'Source', target: 'Target',
    conn_note: 'Showing the {n} newest streams.',
    pause: 'Pause', resume: 'Resume', clear_view: 'Clear view', download: 'Download', no_logs: 'Nothing to show.',

    config_file: 'Config file', config_guide: 'Configuration guide', config_guide_client: 'Client example', config_guide_server: 'Server example',
    config_guide_hint: 'These examples are embedded in the binary and are not your active configuration. Replace all sample values and tokens before use.',
    config_guide_loading: 'Loading example…', close: 'Close',
    validate: 'Validate', save_apply: 'Save and apply', revert: 'Discard changes',
    download_toml: 'Download TOML',
    reload_now: 'Reload config', read_only_note: 'The panel is read-only; editing and actions are disabled.',
    conflict_note: 'The file changed on disk meanwhile. Load the latest version first so nothing is overwritten.',
    load_latest: 'Load latest', backups: 'Backups',
    backups_hint: 'The previous file is kept automatically before every save (last 15).',
    restore: 'Restore', no_backups: 'No backups yet.', unsaved: 'Unsaved changes', saved_state: 'Saved',
    last_modified: 'Last modified', line_col: 'Line {l}, col {c}',
    valid_ok: 'The configuration is valid.', saved_ok: 'Saved. The change is applied within seconds without dropping connections.',
    restored_ok: 'Backup restored; it will be applied shortly.', reload_requested: 'Reload requested.',
    confirm_save_title: 'Save and apply?', confirm_save_text: 'The new configuration is applied by hot-reload. Existing connections stay up.',
    confirm_restore_title: 'Restore this backup?', confirm_restore_text: 'It replaces the current configuration (which is backed up first).',
    confirm_reload_title: 'Reload now?', confirm_reload_text: 'Listeners restart with the same settings; existing connections continue.',
    confirm_clear_title: 'Clear blocked targets?', confirm_clear_text: 'All targets will be tried again.',
    confirm_revoke_title: 'Sign this session out?', confirm_revoke_text: 'That device will have to sign in again.',
    cancel: 'Cancel', confirm: 'Confirm',
    warn_both_roles: 'Both [server] and [client] are set; only [server] runs.',
    warn_admin_removed: 'The [admin] section is removed; the panel becomes unreachable after applying.',
    warn_admin_disabled: 'The panel is disabled in this config; it becomes unreachable after applying.',
    warn_admin_bind_changed: 'The panel listen address changed; sign in at the new address after applying.',
    warn_admin_proxy_changed: 'The trust_proxy setting changed.',
    warn_admin_weak_password: 'The panel password in [admin] is shorter than 10 characters.',

    zone: 'Zone', issued: 'Issued', expires: 'Expires', remaining: 'Remaining', no_certs: 'No certificate found in the certs folder.',
    certs_hint: 'Dates are read from the certificate itself. Renewal is automatic with a Cloudflare or ArvanCloud token.',
    cert_valid: 'Valid', cert_soon: 'Expiring soon', cert_expired: 'Expired', cert_renew: 'Renewal due', days_n: '{n} days',

    current_password: 'Current password', new_password: 'New password', repeat_password: 'Repeat new password', password_rule: 'At least 10 characters',
    save_password: 'Save password', passwords_mismatch: 'The new password and its repetition differ.',
    password_changed: 'Password changed. Other sessions were signed out.',
    password_changed_relogin: 'The password was saved in the [admin] section of the config. The panel restarts with it; please sign in again…',
    active_sessions: 'Active sessions', sessions_hint: 'Devices currently signed in to the panel with this account.',
    this_session: 'This session', revoke: 'Sign out', last_active: 'Last active',

    ago: 'ago', now: 'just now', copy: 'Copy', copied: 'Copied', loading: 'Loading…',
    ok_done: 'Done'
  };

  var DICT = { fa: FA, en: EN };
  var root = document.documentElement;
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } }
  };

  var lang = store.get('gh_lang') === 'en' ? 'en' : 'fa';
  var theme = store.get('gh_theme');
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function t(key, vars) {
    var s = DICT[lang][key];
    if (s === undefined) s = DICT.en[key];
    if (s === undefined) return key;
    if (vars) {
      Object.keys(vars).forEach(function (k) { s = s.split('{' + k + '}').join(String(vars[k])); });
    }
    return s;
  }

  var NS = 'http://www.w3.org/2000/svg';
  var ICONS = {
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M3 3l18 18M10.6 6.1A9.8 9.8 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-3.2 3.9M6.6 6.7C3.9 8.4 2 12 2 12s3.5 6 10 6c1.5 0 2.8-.3 4-.8"/>',
    dashboard: '<rect x="3" y="3" width="8" height="10" rx="2"/><rect x="13" y="3" width="8" height="6" rx="2"/><rect x="13" y="11" width="8" height="10" rx="2"/><rect x="3" y="15" width="8" height="6" rx="2"/>',
    tunnels: '<path d="M3 12h4l3-6 4 12 3-6h4"/>',
    connections: '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.3 11l7.4-4M8.3 13l7.4 4"/>',
    logs: '<path d="M4 6h16M4 12h16M4 18h10"/>',
    config: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
    certs: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
    account: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>'
  };

  function icon(name) {
    var s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('class', 'ico');
    s.setAttribute('aria-hidden', 'true');
    s.innerHTML = ICONS[name] || ''; // static, trusted strings only
    return s;
  }

  function setIcon(el, name) {
    if (!el) return;
    el.textContent = '';
    el.appendChild(icon(name));
  }

  function applyTheme() {
    root.setAttribute('data-theme', theme);
    setIcon(document.getElementById('theme-btn'), theme === 'dark' ? 'sun' : 'moon');
  }

  function apply() {
    root.setAttribute('lang', lang);
    root.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
    document.querySelectorAll('[data-i18n]').forEach(function (el) { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-ph]').forEach(function (el) { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      var v = t(el.getAttribute('data-i18n-title'));
      el.setAttribute('title', v);
      if (el.id === 'lang-btn') el.textContent = v;
    });
    applyTheme();
  }

  function setLang(l) {
    lang = l === 'en' ? 'en' : 'fa';
    store.set('gh_lang', lang);
    apply();
    document.dispatchEvent(new CustomEvent('gh:lang'));
  }

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    store.set('gh_theme', theme);
    applyTheme();
    document.dispatchEvent(new CustomEvent('gh:theme'));
  }

  // Apply direction/theme immediately (before first paint); text is filled once the DOM is ready.
  root.setAttribute('lang', lang);
  root.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
  root.setAttribute('data-theme', theme);

  function bindTools() {
    var lb = document.getElementById('lang-btn');
    var tb = document.getElementById('theme-btn');
    if (lb) lb.addEventListener('click', function () { setLang(lang === 'fa' ? 'en' : 'fa'); });
    if (tb) tb.addEventListener('click', toggleTheme);
  }

  window.GH = {
    t: t, icon: icon, setIcon: setIcon, apply: apply, bindTools: bindTools,
    lang: function () { return lang; },
    theme: function () { return theme; },
    DICT: DICT
  };

  document.addEventListener('DOMContentLoaded', function () { apply(); bindTools(); });
})();
