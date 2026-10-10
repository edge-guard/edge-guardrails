//! Links in email text and HTML: signs of phishing, found locally without any network lookup.

use regex::Regex;

/// Why a link looks dangerous, as bit flags.
pub mod reason {
    /// The address imitates a known brand (a bank, payment app, government site, Microsoft or Google login).
    pub const LOOKALIKE: u32 = 1;
    /// The host is a bare IP address.
    pub const IP_HOST: u32 = 2;
    /// "https://paypal.com@evil.com": everything before the @ is decoration.
    pub const USERINFO: u32 = 4;
    /// Punycode or non-Latin letters in the host: letters that look like others.
    pub const IDN: u32 = 8;
    /// A direct download of a program or script.
    pub const EXECUTABLE: u32 = 16;
    /// javascript:, data: or vbscript: instead of a web address.
    pub const SCRIPT: u32 = 32;
    /// The visible text shows one address and the link goes to another.
    pub const MISMATCH: u32 = 64;
    /// A URL shortener hides the destination: a weak sign on its own.
    pub const SHORTENER: u32 = 128;
    /// Signs strong enough to warn about.
    pub const STRONG: u32 = LOOKALIKE | IP_HOST | USERINFO | IDN | EXECUTABLE | SCRIPT | MISMATCH;

    pub const NAMES: [(u32, &str); 8] = [
        (LOOKALIKE, "lookalike"),
        (IP_HOST, "ip"),
        (USERINFO, "userinfo"),
        (IDN, "idn"),
        (EXECUTABLE, "executable"),
        (SCRIPT, "script"),
        (MISMATCH, "mismatch"),
        (SHORTENER, "shortener"),
    ];
}

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    /// Byte range in the text (0..0 for an HTML link).
    pub start: usize,
    pub end: usize,
    /// Lower-case host, e.g. "www.leumi.co.il".
    pub host: String,
    /// The registrable domain, e.g. "leumi.co.il": what an allow-list compares.
    pub site: String,
    pub reasons: u32,
}

struct Brand {
    /// Matched anywhere in the host: names distinctive enough not to appear by chance.
    contains: &'static [&'static str],
    /// Matched only as a whole part of the host (between dots or hyphens): common words.
    words: &'static [&'static str],
    /// The words are ordinary Hebrew or English words ("leumi" is "national"): under .il they're no sign.
    words_ok_in_il: bool,
    /// The brand's real domains and their subdomains; "google.*" means google.<any suffix>.
    official: &'static [&'static str],
}

const BRANDS: &[Brand] = &[
    Brand {
        contains: &["bankleumi", "leumibank", "leumi-bank", "leumicard", "leumi-card"],
        words: &["leumi"],
        words_ok_in_il: true,
        official: &["leumi.co.il", "bankleumi.co.il", "leumi.com", "leumi-card.co.il"],
    },
    Brand {
        contains: &["bankhapoalim", "hapoalimbank", "poalimbank"],
        words: &["hapoalim", "poalim"],
        words_ok_in_il: true,
        official: &["bankhapoalim.co.il", "bankhapoalim.com", "poalim.co.il"],
    },
    Brand { contains: &["mizrahi-tefahot", "mizrahitefahot", "tefahot"], words: &[], words_ok_in_il: false, official: &["mizrahi-tefahot.co.il"] },
    Brand { contains: &["discountbank", "discount-bank"], words: &[], words_ok_in_il: false, official: &["discountbank.co.il"] },
    Brand { contains: &["isracard"], words: &[], words_ok_in_il: false, official: &["isracard.co.il"] },
    Brand { contains: &["cal-online", "calonline"], words: &[], words_ok_in_il: false, official: &["cal-online.co.il"] },
    Brand { contains: &["paybox"], words: &[], words_ok_in_il: false, official: &["payboxapp.com", "paybox.com"] },
    Brand {
        contains: &["paypal"],
        words: &[],
        words_ok_in_il: false,
        official: &["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"],
    },
    Brand { contains: &["israelpost", "israel-post"], words: &[], words_ok_in_il: false, official: &["israelpost.co.il"] },
    Brand { contains: &[], words: &["gov", "govil"], words_ok_in_il: false, official: &["gov.il", "gov", "gov.uk", "mil"] },
    Brand {
        contains: &["microsoft", "office365", "sharepoint", "onedrive", "outlook365", "hotmail"],
        words: &[],
        words_ok_in_il: false,
        official: &[
            "microsoft.com", "microsoftonline.com", "microsoftonline-p.com", "office.com", "office365.com", "office.net",
            "live.com", "live.net", "outlook.com", "hotmail.com", "sharepoint.com", "sharepointonline.com", "onedrive.com",
            "1drv.ms", "msn.com", "azure.com", "windows.net", "microsoft365.com", "cloud.microsoft", "msauth.net", "msft.net",
        ],
    },
    Brand {
        contains: &[],
        words: &["google", "gmail", "googledrive", "googledocs"],
        words_ok_in_il: true,
        official: &["google.*", "gmail.com", "googlemail.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "youtube.com", "goo.gl", "g.co", "withgoogle.com"],
    },
    Brand { contains: &["icloud", "appleid", "apple-id"], words: &["apple"], words_ok_in_il: true, official: &["apple.com", "icloud.com", "me.com"] },
    Brand {
        contains: &[],
        words: &["amazon"],
        words_ok_in_il: true,
        official: &["amazon.*", "amazonaws.com", "a.co", "amzn.to", "amazon-adsystem.com", "media-amazon.com", "ssl-images-amazon.com"],
    },
    Brand { contains: &["docusign"], words: &[], words_ok_in_il: false, official: &["docusign.com", "docusign.net"] },
    Brand { contains: &["dropbox"], words: &[], words_ok_in_il: false, official: &["dropbox.com", "dropboxusercontent.com", "db.tt"] },
    Brand { contains: &["wetransfer"], words: &[], words_ok_in_il: false, official: &["wetransfer.com", "we.tl"] },
    Brand { contains: &["netflix"], words: &[], words_ok_in_il: false, official: &["netflix.com"] },
    Brand {
        contains: &["facebook", "instagram", "whatsapp"],
        words: &[],
        words_ok_in_il: false,
        official: &["facebook.com", "fb.com", "fb.me", "meta.com", "instagram.com", "whatsapp.com", "whatsapp.net", "wa.me", "fbcdn.net", "facebookmail.com"],
    },
];

/// Two-part public suffixes: the registrable domain under them has three parts.
const SECOND_LEVEL: &[&str] = &[
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il", "k12.il", "idf.il", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br", "co.jp", "com.cn", "com.tr", "co.in", "com.mx", "com.sg", "com.hk",
];

const SHORTENERS: &[&str] = &[
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "v.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "short.io", "tiny.one", "lnkd.in",
];

/// Programs, scripts and macro documents: an email link straight to one is a classic malware trick.
const RISKY_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".jar", ".apk", ".iso", ".img", ".lnk", ".ps1", ".hta", ".docm", ".xlsm",
];

/// Mail security gateways that rewrite links and scan them on click; the original can't be read from them.
const SECURITY_WRAPPERS: &[&str] = &["urldefense.com", "urldefense.proofpoint.com", "mimecastprotect.com", "mimecast.com", "cudasvc.com", "barracudanetworks.com"];

/// Top-level domains recognised in a bare address without http:// or www. (not file extensions like .zip).
const TLDS: &str = "com|net|org|info|biz|io|co|me|app|dev|ai|ly|link|xyz|top|site|online|shop|store|club|live|tech|website|space|click|help|support|services|digital|cloud|email|ru|cn|tk|ml|ga|cf|gq|pw|cc|ws|to|us|uk|de|fr|eu|il";

const MAX_LINKS: usize = 200;

pub struct LinkScanner {
    url_re: Regex,
    bare_re: Regex,
}

impl Default for LinkScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkScanner {
    pub fn new() -> Self {
        // A URL ends at whitespace, brackets, quotes or Hebrew letters (Hebrew text often follows a link directly).
        let url_re = Regex::new(r#"(?i)\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]\p{Hebrew}]+"#).unwrap();
        // "leumi-verify.com/login" without http: an email client turns it into a link too. Not after "@" (emails).
        let bare_re = Regex::new(&format!(
            r#"(?i)(?:^|[^@\w.\-/])((?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+(?:{tlds})\b(?::\d{{2,5}})?(?:/[^\s<>"'`{{}}|\\^\[\]\p{{Hebrew}}]*)?)"#,
            tlds = TLDS
        ))
        .unwrap();
        LinkScanner { url_re, bare_re }
    }

    /// Every link in plain text, with what looks wrong about it.
    pub fn find(&self, text: &str) -> Vec<Link> {
        let mut out: Vec<Link> = Vec::new();
        for m in self.url_re.find_iter(text).take(MAX_LINKS) {
            let raw = trim_trailing(m.as_str());
            if let Some(link) = analyse(raw, m.start(), m.start() + raw.len()) {
                out.push(link);
            }
        }
        for caps in self.bare_re.captures_iter(text).take(MAX_LINKS) {
            let m = caps.get(1).unwrap();
            let raw = trim_trailing(m.as_str());
            let (start, end) = (m.start(), m.start() + raw.len());
            if out.iter().any(|l| start < l.end && l.start < end) {
                continue;
            }
            if let Some(link) = analyse(raw, start, end) {
                out.push(link);
            }
        }
        out.sort_by_key(|l| l.start);
        out
    }

    /// An HTML link: where it really goes (through Outlook/Google redirects), what's wrong with that
    /// address, and whether its visible text shows a different one. None for mailto:, tel:, page
    /// anchors, relative links and links rewritten by a mail security gateway (scanned on click).
    pub fn check_anchor(&self, href: &str, text: &str) -> Option<Link> {
        let href: String = href.chars().filter(|c| !c.is_whitespace() && !c.is_control()).collect();
        let lower = href.to_ascii_lowercase();
        if lower.starts_with("javascript:") || lower.starts_with("data:") || lower.starts_with("vbscript:") {
            return Some(Link { start: 0, end: 0, host: String::new(), site: String::new(), reasons: reason::SCRIPT });
        }
        if !(lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("//") || lower.starts_with("www.")) {
            return None;
        }
        let target = unwrap_redirects(&href)?;
        let mut link = analyse(&target, 0, 0)?;
        if let Some(shown) = self.find(text).into_iter().next() {
            if shown.site != link.site {
                link.reasons |= reason::MISMATCH;
            }
        }
        Some(link)
    }
}

struct UrlParts<'a> {
    host: String,
    userinfo: bool,
    /// Path, query and fragment.
    path: &'a str,
}

fn split_url(url: &str) -> Option<UrlParts<'_>> {
    let head = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    let rest = if head.starts_with("https://") {
        &url[8..]
    } else if head.starts_with("http://") {
        &url[7..]
    } else {
        url.strip_prefix("//").unwrap_or(url)
    };
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (true, &authority[i + 1..]),
        None => (false, authority),
    };
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
            .map_or(hostport, |(h, _)| h),
    };
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(UrlParts { host, userinfo, path })
}

fn analyse(url: &str, start: usize, end: usize) -> Option<Link> {
    let parts = split_url(url)?;
    let site = site_of(&parts.host);
    let mut reasons = 0;
    if parts.userinfo {
        reasons |= reason::USERINFO;
    }
    if is_ip(&parts.host) {
        reasons |= reason::IP_HOST;
    }
    if parts.host.split('.').any(|l| l.starts_with("xn--")) || !parts.host.is_ascii() {
        reasons |= reason::IDN;
    }
    if is_lookalike(&parts.host, &site) {
        reasons |= reason::LOOKALIKE;
    }
    let file = parts.path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    if RISKY_EXTENSIONS.iter().any(|ext| file.ends_with(ext)) {
        reasons |= reason::EXECUTABLE;
    }
    if SHORTENERS.contains(&site.as_str()) || SHORTENERS.contains(&parts.host.as_str()) {
        reasons |= reason::SHORTENER;
    }
    Some(Link { start, end, host: parts.host, site, reasons })
}

fn is_ip(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    host.contains(':')
        || (parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
        || (!host.is_empty() && host.chars().all(|c| c.is_ascii_digit()))
}

/// The registrable domain ("leumi.co.il" for "www.leumi.co.il").
pub fn site_of(host: &str) -> String {
    if is_ip(host) {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n <= 2 {
        return labels.join(".");
    }
    let last2 = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if SECOND_LEVEL.contains(&last2.as_str()) {
        labels[n - 3..].join(".")
    } else {
        last2
    }
}

/// Look-alike digits and letter pairs read as the letters they imitate ("paypa1" → "paypal", "rn" → "m").
fn deconfuse(host: &str) -> String {
    host.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            c => c,
        })
        .collect::<String>()
        .replace("rn", "m")
        .replace("vv", "w")
}

fn is_official(host: &str, site: &str, official: &str) -> bool {
    if let Some(prefix) = official.strip_suffix('*') {
        return site.starts_with(prefix);
    }
    host == official || site == official || host.ends_with(&format!(".{official}"))
}

/// Israeli registries open only to government, municipalities, academia and the army.
const RESTRICTED_IL: &[&str] = &["gov.il", "muni.il", "ac.il", "idf.il", "k12.il"];

fn is_lookalike(host: &str, site: &str) -> bool {
    if RESTRICTED_IL.iter().any(|r| site == *r || site.ends_with(&format!(".{r}"))) {
        return false;
    }
    let plain = deconfuse(host);
    let israeli = site.ends_with(".il");
    let has_word = |s: &str, w: &str| s.split(['.', '-', '_']).any(|part| part == w);
    BRANDS.iter().any(|b| {
        let named = b.contains.iter().any(|t| host.contains(t) || plain.contains(t))
            || (!(israeli && b.words_ok_in_il) && b.words.iter().any(|w| has_word(host, w) || has_word(&plain, w)));
        named && !b.official.iter().any(|o| is_official(host, site, o))
    })
}

/// Follows Outlook Safe Links, Google and Facebook redirects to the real destination. None when a
/// security gateway wrapped the link (it can't be unwrapped, and the gateway scans it on click).
fn unwrap_redirects(href: &str) -> Option<String> {
    let mut url = href.to_string();
    for _ in 0..3 {
        let inner = {
            let Some(parts) = split_url(&url) else { break };
            let site = site_of(&parts.host);
            if SECURITY_WRAPPERS.iter().any(|w| site == *w || parts.host == *w) {
                return None;
            }
            if parts.host.ends_with("safelinks.protection.outlook.com") {
                query_param(parts.path, "url")
            } else if site.starts_with("google.") && parts.path.starts_with("/url") {
                query_param(parts.path, "q").or_else(|| query_param(parts.path, "url"))
            } else if parts.host == "l.facebook.com" || parts.host == "lm.facebook.com" {
                query_param(parts.path, "u")
            } else {
                None
            }
        };
        match inner {
            Some(next) if next.contains("://") => url = next,
            _ => break,
        }
    }
    Some(url)
}

fn query_param(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or("");
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_decode(value))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn trim_trailing(s: &str) -> &str {
    let mut end = s.len();
    while let Some(c) = s[..end].chars().next_back() {
        let unbalanced = c == ')' && !s[..end].contains('(');
        if matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | '»' | '”' | '’') || unbalanced {
            end -= c.len_utf8();
        } else {
            break;
        }
    }
    &s[..end]
}

fn reason_names(reasons: u32) -> String {
    reason::NAMES
        .iter()
        .filter(|(bit, _)| reasons & bit != 0)
        .map(|(_, name)| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Links as JSON: position, host, registrable domain and reasons (never the full address).
pub fn links_json(links: &[Link]) -> String {
    let items: Vec<String> = links
        .iter()
        .map(|l| {
            format!(
                r#"{{"start":{},"end":{},"host":"{}","site":"{}","reasons":[{}]}}"#,
                l.start,
                l.end,
                json_escape(&l.host),
                json_escape(&l.site),
                reason_names(l.reasons)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

impl LinkScanner {
    /// HTML links given as lines of "href<TAB>visible text": JSON for the ones with any reason, by line index.
    pub fn anchors_json(&self, input: &str) -> String {
        let items: Vec<String> = input
            .lines()
            .take(MAX_LINKS)
            .enumerate()
            .filter_map(|(i, line)| {
                let (href, text) = line.split_once('\t').unwrap_or((line, ""));
                let link = self.check_anchor(href, text)?;
                (link.reasons != 0).then(|| {
                    format!(
                        r#"{{"i":{i},"host":"{}","site":"{}","reasons":[{}]}}"#,
                        json_escape(&link.host),
                        json_escape(&link.site),
                        reason_names(link.reasons)
                    )
                })
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::reason::*;
    use super::*;

    fn reasons_of(url: &str) -> u32 {
        let found = LinkScanner::new().find(url);
        assert_eq!(found.len(), 1, "{url}: {found:?}");
        found[0].reasons
    }

    #[test]
    fn real_sites_are_clean() {
        for url in [
            "https://www.leumi.co.il/he/login",
            "https://login.microsoftonline.com/common/oauth2",
            "https://docs.google.com/document/d/abc",
            "https://www.google.co.il/maps",
            "https://www.gov.il/he/service/pay",
            "https://www.paypal.com/il/home",
            "https://www.leumit.co.il",
            "https://www.sherut-leumi.co.il/about",
            "https://www.btl.gov.il/benefits",
            "https://google-ads-expert.co.il",
            "https://maxstock.co.il/sale",
            "https://pineapple-design.co.il",
            "https://wa.me/972501234567",
            "https://www.mybiz.co.il/catalog.pdf",
        ] {
            assert_eq!(reasons_of(url), 0, "{url}");
        }
    }

    #[test]
    fn lookalikes_of_banks_payments_government_and_logins() {
        for url in [
            "https://leumi-secure.co/login",
            "https://www.bankhapoalim-verify.com",
            "http://paypa1.com/signin",
            "https://microsoft-support.help/reset",
            "https://office365-login.net",
            "https://docs.google.com.evil.ru/x",
            "https://gov-il.info/pay",
            "https://gov.il.payments-online.com",
            "https://apple-id-verify.com",
            "https://isracard.secure-update.net",
            "https://bankleumi-il.com/verify",
            "https://leumi.co.il.verify-account.xyz",
            "https://bankleumi-secure.co.il",
        ] {
            assert_eq!(reasons_of(url) & LOOKALIKE, LOOKALIKE, "{url}");
        }
    }

    #[test]
    fn ip_userinfo_punycode_downloads_and_shorteners() {
        assert_eq!(reasons_of("http://192.168.1.10/invoice"), IP_HOST);
        assert_eq!(reasons_of("https://www.paypal.com@evil.example/x") & USERINFO, USERINFO);
        assert_eq!(reasons_of("https://xn--pypal-4ve.com/") & IDN, IDN);
        assert_eq!(reasons_of("https://раураl.com/") & IDN, IDN);
        assert_eq!(reasons_of("https://files.example.com/Invoice.EXE?dl=1"), EXECUTABLE);
        assert_eq!(reasons_of("https://bit.ly/3abc"), SHORTENER);
        assert_eq!(SHORTENER & STRONG, 0);
    }

    #[test]
    fn finds_links_in_text_without_emails_or_file_names() {
        let s = LinkScanner::new();
        let text = "שלום, האתר שלנו www.mybiz.co.il ואפשר גם leumi-verify.com/login. מייל: dana@acme.co.il, קובץ catalog.pdf, Node.js.";
        let found = s.find(text);
        let hosts: Vec<&str> = found.iter().map(|l| l.host.as_str()).collect();
        assert_eq!(hosts, vec!["www.mybiz.co.il", "leumi-verify.com"]);
        assert_eq!(&text[found[1].start..found[1].end], "leumi-verify.com/login");
        assert_eq!(found[0].site, "mybiz.co.il");
        // Hebrew straight after a link, and closing punctuation, aren't part of it.
        let found = s.find("ראו https://example.com/a)לפרטים, או (https://example.com/b).");
        assert_eq!(found.iter().map(|l| l.end - l.start).collect::<Vec<_>>(), vec![21, 21]);
    }

    #[test]
    fn html_links_whose_text_shows_another_address() {
        let s = LinkScanner::new();
        let r = |href: &str, text: &str| s.check_anchor(href, text).map(|l| l.reasons);
        assert_eq!(r("https://evil.example/login", "https://www.leumi.co.il"), Some(MISMATCH));
        assert_eq!(r("https://www.leumi.co.il/he", "leumi.co.il"), Some(0));
        assert_eq!(r("https://evil.example/login", "לחצו כאן לאישור"), Some(0));
        assert_eq!(r("javascript:alert(1)", "click"), Some(SCRIPT));
        assert_eq!(r("mailto:dana@acme.co.il", "dana@acme.co.il"), None);
        assert_eq!(r("#top", "top"), None);
        // Outlook Safe Links are unwrapped to the real destination.
        let wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.leumi.co.il%2Fhe&data=05%7C02";
        assert_eq!(r(wrapped, "www.leumi.co.il"), Some(0));
        let wrapped_evil = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fleumi-verify.com%2F&data=05";
        assert_eq!(r(wrapped_evil, "www.leumi.co.il"), Some(MISMATCH | LOOKALIKE));
        // A security gateway's rewritten link can't be read; it's scanned on click.
        assert_eq!(r("https://urldefense.com/v3/__https://x.example__;!!abc", "www.leumi.co.il"), None);
    }

    #[test]
    fn anchors_json_reports_only_suspicious_lines() {
        let s = LinkScanner::new();
        let input = "https://www.mybiz.co.il\tהאתר שלנו\nhttps://evil.example/x\twww.leumi.co.il\nmailto:a@b.co\ta@b.co";
        assert_eq!(s.anchors_json(input), r#"[{"i":1,"host":"evil.example","site":"evil.example","reasons":["mismatch"]}]"#);
    }
}
