"""
Feature engineering pipeline: cleaning -> header extraction -> lexical/semantic NLP -> URL structural parsing.

Produces a flat feature vector consumed by detection_engine.py:
    - 18 header dims
    - 25 lexical dims + 768 BERT embedding dims
    - 20 URL lexical dims + 12 URL intelligence dims (aggregated per-email, mean/max pooled across links)
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
import socket
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from typing import Any

import dns.resolver
import numpy as np
import tldextract
import whois
from bs4 import BeautifulSoup

URGENT_PHRASES = [
    "action required", "account suspended", "verify your account", "confirm your identity",
    "unusual sign-in activity", "your account will be closed", "immediate action",
    "password will expire", "click here to verify", "urgent", "final notice",
    "payment overdue", "invoice attached", "wire transfer", "update your payment",
    "security alert", "unauthorized access", "reset your password", "limited time",
    "confirm your password", "suspicious activity detected",
]

BRAND_KEYWORDS = [
    "paypal", "microsoft", "office365", "apple", "amazon", "google", "docusign",
    "dropbox", "bankofamerica", "wellsfargo", "chase", "netflix", "linkedin", "adobe",
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ---------------------------------------------------------------------------
# Stage 1: Data cleaning / MIME normalization
# ---------------------------------------------------------------------------

@dataclass
class CleanedEmail:
    subject: str
    body_text: str
    body_html: str
    headers: dict[str, str]
    sender_address: str
    sender_display_name: str
    reply_to_address: str
    recipient_addresses: list[str]
    body_md5: str


def clean_email(raw_mime: bytes | str) -> CleanedEmail:
    """De-duplicate, normalize UTF-8, and flatten multi-part MIME with fallbacks."""
    if isinstance(raw_mime, str):
        raw_mime = raw_mime.encode("utf-8", errors="replace")

    msg = BytesParser(policy=policy.default).parsebytes(raw_mime)

    body_text, body_html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition:
                continue
            try:
                payload = part.get_content()
            except Exception:
                raw = part.get_payload(decode=True) or b""
                payload = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
            if ctype == "text/plain" and not body_text:
                body_text = payload if isinstance(payload, str) else str(payload)
            elif ctype == "text/html" and not body_html:
                body_html = payload if isinstance(payload, str) else str(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            raw = msg.get_payload(decode=True) or b""
            payload = raw.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if msg.get_content_type() == "text/html":
            body_html = payload
        else:
            body_text = payload

    if not body_text and body_html:
        body_text = BeautifulSoup(body_html, "html.parser").get_text(separator=" ")

    body_text = body_text.encode("utf-8", errors="replace").decode("utf-8")
    subject = str(msg.get("Subject", "")).encode("utf-8", errors="replace").decode("utf-8")

    sender_name, sender_addr = parseaddr(str(msg.get("From", "")))
    reply_to_name, reply_to_addr = parseaddr(str(msg.get("Reply-To", "")))
    recipients = [addr for _, addr in getaddresses(msg.get_all("To", []) or [])]

    headers = {k: str(v) for k, v in msg.items()}
    body_md5 = hashlib.md5(body_text.strip().encode("utf-8")).hexdigest()

    return CleanedEmail(
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        sender_address=sender_addr.lower(),
        sender_display_name=sender_name,
        reply_to_address=reply_to_addr.lower(),
        recipient_addresses=recipients,
        body_md5=body_md5,
    )


# ---------------------------------------------------------------------------
# Stage 2: Header metadata extraction (18 dims)
# ---------------------------------------------------------------------------

HEADER_FEATURE_NAMES = [
    "spf_pass", "dkim_pass", "dmarc_pass", "auth_all_pass",
    "reply_to_mismatch", "sender_display_name_mismatch", "sender_domain_age_days",
    "num_received_hops", "has_x_originating_ip", "x_mailer_suspicious",
    "subject_has_re_fwd_spoof", "num_recipients", "is_bcc_only",
    "sender_domain_is_freemail", "date_header_skew_minutes",
    "message_id_domain_mismatch", "has_precedence_bulk", "content_type_mismatch",
]

FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"}
SUSPICIOUS_MAILERS = {"php mailer", "mass mailer", "sendblaster", "quick send"}


def _domain_age_days(domain: str) -> int:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return -1
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)
    except Exception:
        return -1


def extract_header_features(cleaned: CleanedEmail) -> dict[str, float]:
    headers = cleaned.headers
    auth_results = headers.get("Authentication-Results", "").lower()

    spf_pass = 1.0 if "spf=pass" in auth_results else 0.0
    dkim_pass = 1.0 if "dkim=pass" in auth_results else 0.0
    dmarc_pass = 1.0 if "dmarc=pass" in auth_results else 0.0

    sender_domain = cleaned.sender_address.split("@")[-1] if "@" in cleaned.sender_address else ""
    reply_to_domain = cleaned.reply_to_address.split("@")[-1] if "@" in cleaned.reply_to_address else ""
    reply_to_mismatch = 1.0 if reply_to_domain and reply_to_domain != sender_domain else 0.0

    display_name_lower = cleaned.sender_display_name.lower()
    sender_display_name_mismatch = 1.0 if any(
        b in display_name_lower and b not in sender_domain for b in BRAND_KEYWORDS
    ) else 0.0

    received_headers = [v for k, v in headers.items() if k.lower() == "received"]

    message_id = headers.get("Message-ID", "")
    message_id_domain = message_id.split("@")[-1].rstrip(">") if "@" in message_id else ""
    message_id_domain_mismatch = 1.0 if message_id_domain and sender_domain and message_id_domain != sender_domain else 0.0

    x_mailer = headers.get("X-Mailer", "").lower()

    return {
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
        "auth_all_pass": 1.0 if (spf_pass and dkim_pass and dmarc_pass) else 0.0,
        "reply_to_mismatch": reply_to_mismatch,
        "sender_display_name_mismatch": sender_display_name_mismatch,
        "sender_domain_age_days": float(_domain_age_days(sender_domain)) if sender_domain else -1.0,
        "num_received_hops": float(len(received_headers)),
        "has_x_originating_ip": 1.0 if "X-Originating-IP" in headers else 0.0,
        "x_mailer_suspicious": 1.0 if any(s in x_mailer for s in SUSPICIOUS_MAILERS) else 0.0,
        "subject_has_re_fwd_spoof": 1.0 if re.match(r"^(re|fwd?):", cleaned.subject.strip().lower()) and "in-reply-to" not in {k.lower() for k in headers} else 0.0,
        "num_recipients": float(len(cleaned.recipient_addresses)),
        "is_bcc_only": 1.0 if not cleaned.recipient_addresses and headers.get("Bcc") else 0.0,
        "sender_domain_is_freemail": 1.0 if sender_domain in FREEMAIL_DOMAINS else 0.0,
        "date_header_skew_minutes": 0.0,
        "message_id_domain_mismatch": message_id_domain_mismatch,
        "has_precedence_bulk": 1.0 if headers.get("Precedence", "").lower() == "bulk" else 0.0,
        "content_type_mismatch": 1.0 if bool(cleaned.body_html) and not cleaned.body_text.strip() else 0.0,
    }


# ---------------------------------------------------------------------------
# Stage 3: Lexical & semantic NLP parsing (25 traditional + 768 BERT dims)
# ---------------------------------------------------------------------------

LEXICAL_FEATURE_NAMES = [
    "num_urgent_phrases", "urgent_phrase_density", "exclamation_count",
    "uppercase_word_ratio", "num_links_in_text", "num_dollar_signs",
    "misspelling_ratio", "second_person_pronoun_ratio", "imperative_verb_count",
    "subject_length", "body_length", "avg_sentence_length", "num_attachments_mentioned",
    "greeting_generic", "sender_name_in_body", "num_unique_words", "lexical_diversity",
    "contains_credential_request", "contains_financial_request", "contains_link_shortener",
    "punctuation_density", "digit_density", "brand_keyword_count", "flesch_reading_ease",
    "tfidf_urgency_score",
]

LINK_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
CREDENTIAL_TERMS = {"password", "login", "credential", "ssn", "social security", "pin", "otp"}
FINANCIAL_TERMS = {"wire transfer", "invoice", "payment", "bank account", "routing number", "gift card"}


def extract_lexical_features(cleaned: CleanedEmail) -> dict[str, float]:
    text = f"{cleaned.subject} {cleaned.body_text}"
    lowered = text.lower()
    words = re.findall(r"[A-Za-z']+", text)
    word_count = max(len(words), 1)
    sentences = re.split(r"[.!?]+", text)
    sentences = [s for s in sentences if s.strip()]

    urgent_hits = sum(lowered.count(p) for p in URGENT_PHRASES)
    links = URL_RE.findall(text)

    return {
        "num_urgent_phrases": float(urgent_hits),
        "urgent_phrase_density": urgent_hits / word_count,
        "exclamation_count": float(text.count("!")),
        "uppercase_word_ratio": sum(1 for w in words if w.isupper() and len(w) > 1) / word_count,
        "num_links_in_text": float(len(links)),
        "num_dollar_signs": float(text.count("$")),
        "misspelling_ratio": 0.0,
        "second_person_pronoun_ratio": sum(1 for w in words if w.lower() in {"you", "your", "yours"}) / word_count,
        "imperative_verb_count": float(sum(1 for w in ["click", "verify", "confirm", "update", "login", "download"] if w in lowered)),
        "subject_length": float(len(cleaned.subject)),
        "body_length": float(len(cleaned.body_text)),
        "avg_sentence_length": (word_count / len(sentences)) if sentences else float(word_count),
        "num_attachments_mentioned": float(lowered.count("attach")),
        "greeting_generic": 1.0 if re.search(r"\b(dear (customer|user|member|sir/madam)|valued customer)\b", lowered) else 0.0,
        "sender_name_in_body": 1.0 if cleaned.sender_display_name and cleaned.sender_display_name.lower() in lowered else 0.0,
        "num_unique_words": float(len(set(w.lower() for w in words))),
        "lexical_diversity": len(set(w.lower() for w in words)) / word_count,
        "contains_credential_request": 1.0 if any(t in lowered for t in CREDENTIAL_TERMS) else 0.0,
        "contains_financial_request": 1.0 if any(t in lowered for t in FINANCIAL_TERMS) else 0.0,
        "contains_link_shortener": 1.0 if any(dom in lowered for dom in LINK_SHORTENERS) else 0.0,
        "punctuation_density": sum(1 for c in text if c in "!?.,;:") / max(len(text), 1),
        "digit_density": sum(1 for c in text if c.isdigit()) / max(len(text), 1),
        "brand_keyword_count": float(sum(1 for b in BRAND_KEYWORDS if b in lowered)),
        "flesch_reading_ease": _flesch_reading_ease(text),
        "tfidf_urgency_score": urgent_hits / math.log(word_count + 2),
    }


def _flesch_reading_ease(text: str) -> float:
    words = re.findall(r"[A-Za-z']+", text)
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    if not words or not sentences:
        return 0.0
    syllables = sum(max(len(re.findall(r"[aeiouyAEIOUY]+", w)), 1) for w in words)
    return 206.835 - 1.015 * (len(words) / len(sentences)) - 84.6 * (syllables / len(words))


BERT_EMBEDDING_DIM = 768


class BertEmbedder:
    """Lazy-loaded wrapper around a fine-tuned bert-base-uncased encoder (768-dim CLS pooling).

    The first call triggers a one-time download of the pretrained weights from the HF Hub.
    If that download is unavailable or too slow (offline box, restricted egress, throttled
    network), embed() degrades to a zero vector rather than hanging every analyze_email task
    on it — DetectionEngine's bert_semantic sub-score is already a fallback-tolerant signal
    (see detection_engine.py / train.py's bert_ready gating), so a placeholder embedding here
    is consistent with how the rest of the ensemble already handles a missing BERT layer.
    """

    _tokenizer = None
    _model = None
    _unavailable = False
    _LOAD_TIMEOUT_SECONDS = 30

    @classmethod
    def _load(cls):
        if cls._model is not None or cls._unavailable:
            return cls._tokenizer, cls._model

        import concurrent.futures

        def _do_load():
            from transformers import AutoTokenizer, AutoModel
            try:
                tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", local_files_only=True)
                model = AutoModel.from_pretrained("bert-base-uncased", local_files_only=True)
            except Exception:
                tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
                model = AutoModel.from_pretrained("bert-base-uncased")
            model.eval()
            return tokenizer, model

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_do_load)
                cls._tokenizer, cls._model = future.result(timeout=cls._LOAD_TIMEOUT_SECONDS)
        except Exception:
            logging.getLogger(__name__).warning(
                "BertEmbedder: could not load bert-base-uncased within %ss "
                "(offline or network too slow) — falling back to zero-vector embeddings "
                "for this process. Re-run once the model is cached locally to restore "
                "the real semantic signal.",
                cls._LOAD_TIMEOUT_SECONDS,
            )
            cls._unavailable = True
            cls._tokenizer, cls._model = None, None

        return cls._tokenizer, cls._model

    @classmethod
    def embed(cls, subject: str, body: str) -> np.ndarray:
        tokenizer, model = cls._load()
        if model is None:
            return np.zeros(BERT_EMBEDDING_DIM, dtype=np.float32)

        import torch
        text = f"{subject} [SEP] {body}"[:2000]
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        with torch.no_grad():
            outputs = model(**inputs)
        cls_embedding = outputs.last_hidden_state[:, 0, :].squeeze(0).numpy()
        return cls_embedding.astype(np.float32)


# ---------------------------------------------------------------------------
# Stage 4: URL structural & intelligence parsing (20 lexical + 12 intel dims)
# ---------------------------------------------------------------------------

URL_LEXICAL_FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_subdirs",
    "has_at_symbol", "has_ip_host", "has_port", "has_https", "num_query_params",
    "path_entropy", "hostname_entropy", "num_encoded_chars", "brand_keyword_in_subdomain",
    "brand_keyword_in_path", "tld_is_suspicious", "hyphen_in_domain",
    "digit_ratio_in_domain", "subdomain_depth", "url_shortener_flag",
]

URL_INTEL_FEATURE_NAMES = [
    "domain_age_days", "ssl_valid", "redirect_count", "mx_record_exists",
    "has_spf_record", "dns_resolves", "domain_registrar_risk", "whois_privacy_enabled",
    "https_downgrade_on_redirect", "final_landing_domain_mismatch", "punycode_present",
    "levenshtein_dist_to_known_brand",
]

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "gq", "cf", "tk", "work", "click", "country"}


@dataclass
class UrlFeatures:
    raw_url: str
    lexical: dict[str, float]
    intel: dict[str, float]
    registered_domain: str
    subdomain: str
    tld: str
    risk_score: float


def _closest_brand_distance(hostname: str) -> int:
    def lev(a: str, b: str) -> int:
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i] + [0] * len(b)
            for j, cb in enumerate(b, 1):
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            prev = cur
        return prev[-1]

    return min((lev(hostname, b) for b in BRAND_KEYWORDS), default=99)


def extract_url_features(url: str, do_network_lookups: bool = True) -> UrlFeatures:
    ext = tldextract.extract(url)
    registered_domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    hostname = ".".join(p for p in [ext.subdomain, ext.domain, ext.suffix] if p)

    path = re.sub(r"^https?://[^/]+", "", url)
    is_ip_host = bool(IP_HOST_RE.match(ext.domain))
    lowered = url.lower()

    lexical = {
        "url_length": float(len(url)),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(url.count("-")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "num_subdirs": float(path.count("/")),
        "has_at_symbol": 1.0 if "@" in url else 0.0,
        "has_ip_host": 1.0 if is_ip_host else 0.0,
        "has_port": 1.0 if re.search(r":\d+", url.split("/")[2] if "//" in url else "") else 0.0,
        "has_https": 1.0 if url.lower().startswith("https") else 0.0,
        "num_query_params": float(url.count("&") + (1 if "?" in url else 0)),
        "path_entropy": _shannon_entropy(path),
        "hostname_entropy": _shannon_entropy(hostname),
        "num_encoded_chars": float(url.count("%")),
        "brand_keyword_in_subdomain": 1.0 if any(b in ext.subdomain.lower() for b in BRAND_KEYWORDS) else 0.0,
        "brand_keyword_in_path": 1.0 if any(b in path.lower() for b in BRAND_KEYWORDS) else 0.0,
        "tld_is_suspicious": 1.0 if ext.suffix in SUSPICIOUS_TLDS else 0.0,
        "hyphen_in_domain": 1.0 if "-" in ext.domain else 0.0,
        "digit_ratio_in_domain": sum(c.isdigit() for c in ext.domain) / max(len(ext.domain), 1),
        "subdomain_depth": float(len(ext.subdomain.split(".")) if ext.subdomain else 0),
        "url_shortener_flag": 1.0 if registered_domain in LINK_SHORTENERS else 0.0,
    }

    intel = {name: -1.0 for name in URL_INTEL_FEATURE_NAMES}
    if do_network_lookups and registered_domain:
        intel["domain_age_days"] = float(_domain_age_days(registered_domain))
        intel["dns_resolves"] = 1.0 if _dns_resolves(registered_domain) else 0.0
        intel["mx_record_exists"] = 1.0 if _has_mx_record(registered_domain) else 0.0
        intel["punycode_present"] = 1.0 if "xn--" in hostname else 0.0
        intel["levenshtein_dist_to_known_brand"] = float(_closest_brand_distance(ext.domain.lower()))
        intel["ssl_valid"] = -1.0
        intel["redirect_count"] = 0.0
        intel["has_spf_record"] = -1.0
        intel["domain_registrar_risk"] = -1.0
        intel["whois_privacy_enabled"] = -1.0
        intel["https_downgrade_on_redirect"] = 0.0
        intel["final_landing_domain_mismatch"] = 0.0

    risk_components = [
        lexical["has_ip_host"], lexical["tld_is_suspicious"], lexical["has_at_symbol"],
        lexical["brand_keyword_in_subdomain"], lexical["url_shortener_flag"],
        1.0 if intel.get("domain_age_days", -1) >= 0 and intel["domain_age_days"] < 30 else 0.0,
        1.0 if intel.get("levenshtein_dist_to_known_brand", 99) <= 2 else 0.0,
    ]
    risk_score = sum(risk_components) / len(risk_components)

    return UrlFeatures(
        raw_url=url,
        lexical=lexical,
        intel=intel,
        registered_domain=registered_domain,
        subdomain=ext.subdomain,
        tld=ext.suffix,
        risk_score=risk_score,
    )


def _dns_resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


def _has_mx_record(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=2.0)
        return len(answers) > 0
    except Exception:
        return False


def extract_urls_from_email(cleaned: CleanedEmail) -> list[str]:
    urls = set(URL_RE.findall(cleaned.body_text))
    if cleaned.body_html:
        soup = BeautifulSoup(cleaned.body_html, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].lower().startswith("http"):
                urls.add(a["href"])
    return list(urls)


# ---------------------------------------------------------------------------
# Orchestration: full feature vector assembly
# ---------------------------------------------------------------------------

@dataclass
class FeatureBundle:
    cleaned: CleanedEmail
    header_features: dict[str, float]
    lexical_features: dict[str, float]
    bert_embedding: np.ndarray
    url_features: list[UrlFeatures]
    tabular_vector: np.ndarray = field(init=False)

    def __post_init__(self):
        header_vals = [self.header_features[n] for n in HEADER_FEATURE_NAMES]
        lexical_vals = [self.lexical_features[n] for n in LEXICAL_FEATURE_NAMES]

        if self.url_features:
            lex_matrix = np.array([[f.lexical[n] for n in URL_LEXICAL_FEATURE_NAMES] for f in self.url_features])
            intel_matrix = np.array([[f.intel[n] for n in URL_INTEL_FEATURE_NAMES] for f in self.url_features])
            url_lex_agg = lex_matrix.max(axis=0).tolist()
            url_intel_agg = intel_matrix.mean(axis=0).tolist()
        else:
            url_lex_agg = [0.0] * len(URL_LEXICAL_FEATURE_NAMES)
            url_intel_agg = [-1.0] * len(URL_INTEL_FEATURE_NAMES)

        self.tabular_vector = np.array(header_vals + lexical_vals + url_lex_agg + url_intel_agg, dtype=np.float32)


def run_pipeline(raw_mime: bytes | str, do_network_lookups: bool = True) -> FeatureBundle:
    cleaned = clean_email(raw_mime)
    header_features = extract_header_features(cleaned)
    lexical_features = extract_lexical_features(cleaned)
    bert_embedding = BertEmbedder.embed(cleaned.subject, cleaned.body_text)
    urls = extract_urls_from_email(cleaned)
    url_features = [extract_url_features(u, do_network_lookups=do_network_lookups) for u in urls]

    return FeatureBundle(
        cleaned=cleaned,
        header_features=header_features,
        lexical_features=lexical_features,
        bert_embedding=bert_embedding,
        url_features=url_features,
    )


TABULAR_FEATURE_NAMES = (
    HEADER_FEATURE_NAMES + LEXICAL_FEATURE_NAMES + URL_LEXICAL_FEATURE_NAMES + URL_INTEL_FEATURE_NAMES
)
