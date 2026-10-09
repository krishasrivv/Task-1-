"""
ThreatIntel AI — Flask Backend
Endpoints: /api/health, /api/lookup, /api/chat
Integrations: VirusTotal v3, AlienVault OTX, NVIDIA AI
"""

import os
import re
import hashlib
import json
import time
from urllib.parse import quote as url_quote
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests as http_requests

# Ensure backend/.env or workspace .env is reliably loaded
_backend_dir = Path(__file__).resolve().parent
_backend_env = _backend_dir / ".env"
_root_env = _backend_dir.parent / ".env"

if _backend_env.exists():
    load_dotenv(dotenv_path=_backend_env, override=True)
elif _root_env.exists():
    load_dotenv(dotenv_path=_root_env, override=True)
else:
    load_dotenv(override=True)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

import base64

def _clean_key(val: str) -> str:
    return val.strip().strip("'\"") if val else ""

def _read_env_file() -> dict:
    env_dict = {}
    target = _backend_env if _backend_env.exists() else _root_env
    if target.exists():
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        env_dict[k.strip()] = v.strip().strip("'\"")
        except Exception:
            pass
    return env_dict

def _is_placeholder(val: str) -> bool:
    if not val:
        return True
    low = val.lower().strip()
    return low.startswith("your_") or low.endswith("_here") or "your_virustotal_api_key_here" in low or "your_alienvault_otx_api_key_here" in low or "your_nvidia_api_key_here" in low

def get_vt_api_key() -> str:
    live = _read_env_file()
    return _clean_key(live.get("VIRUSTOTAL_API_KEY") or live.get("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY") or "")

def get_otx_api_key() -> str:
    live = _read_env_file()
    return _clean_key(live.get("ALIENVAULT_OTX_API_KEY") or live.get("OTX_API_KEY") or os.getenv("ALIENVAULT_OTX_API_KEY") or os.getenv("OTX_API_KEY") or "")

def get_nvidia_api_key() -> str:
    live = _read_env_file()
    return _clean_key(live.get("NVIDIA_API_KEY") or os.getenv("NVIDIA_API_KEY") or "")

def get_nvidia_model() -> str:
    live = _read_env_file()
    return _clean_key(live.get("NVIDIA_MODEL") or os.getenv("NVIDIA_MODEL") or "meta/llama-3.2-11b-vision-instruct")

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"
NVIDIA_BASE = "https://integrate.api.nvidia.com/v1/chat/completions"

REQUEST_TIMEOUT = 20  # seconds


# ---------------------------------------------------------------------------
# Helpers – input validation
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
)
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def detect_indicator_type(value: str) -> str | None:
    """Return 'ip', 'domain', 'url', 'hash' or None."""
    value = value.strip()
    if _IPV4_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "hash"
    if _URL_RE.match(value):
        return "url"
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


def sanitize(value: str) -> str:
    """Basic sanitization — strip and limit length."""
    return value.strip()[:2048]


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------
def _vt_headers():
    return {"x-apikey": get_vt_api_key(), "Accept": "application/json"}


def _vt_lookup_ip(ip: str) -> dict:
    try:
        r = http_requests.get(
            f"{VT_BASE}/ip_addresses/{ip}", headers=_vt_headers(), timeout=REQUEST_TIMEOUT
        )
        return _normalize_vt(r, "ip", ip)
    except http_requests.exceptions.Timeout:
        return {"source": "virustotal", "indicator_type": "ip", "indicator": ip, "found": False, "error": "VirusTotal request timed out."}
    except http_requests.exceptions.RequestException as exc:
        return {"source": "virustotal", "indicator_type": "ip", "indicator": ip, "found": False, "error": f"VirusTotal connection error: {str(exc)[:100]}"}


def _vt_lookup_domain(domain: str) -> dict:
    try:
        r = http_requests.get(
            f"{VT_BASE}/domains/{domain}", headers=_vt_headers(), timeout=REQUEST_TIMEOUT
        )
        return _normalize_vt(r, "domain", domain)
    except http_requests.exceptions.Timeout:
        return {"source": "virustotal", "indicator_type": "domain", "indicator": domain, "found": False, "error": "VirusTotal request timed out."}
    except http_requests.exceptions.RequestException as exc:
        return {"source": "virustotal", "indicator_type": "domain", "indicator": domain, "found": False, "error": f"VirusTotal connection error: {str(exc)[:100]}"}


def _vt_lookup_url(url: str) -> dict:
    try:
        # VirusTotal v3 URL ID is base64url-encoded URL without padding '='
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = http_requests.get(
            f"{VT_BASE}/urls/{url_id}", headers=_vt_headers(), timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 404:
            # Submit URL for analysis if not previously analyzed
            http_requests.post(
                f"{VT_BASE}/urls",
                headers=_vt_headers(),
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            time.sleep(1.5)
            r = http_requests.get(
                f"{VT_BASE}/urls/{url_id}", headers=_vt_headers(), timeout=REQUEST_TIMEOUT
            )
        return _normalize_vt(r, "url", url)
    except http_requests.exceptions.Timeout:
        return {"source": "virustotal", "indicator_type": "url", "indicator": url, "found": False, "error": "VirusTotal request timed out."}
    except http_requests.exceptions.RequestException as exc:
        return {"source": "virustotal", "indicator_type": "url", "indicator": url, "found": False, "error": f"VirusTotal connection error: {str(exc)[:100]}"}


def _vt_lookup_hash(file_hash: str) -> dict:
    try:
        r = http_requests.get(
            f"{VT_BASE}/files/{file_hash}", headers=_vt_headers(), timeout=REQUEST_TIMEOUT
        )
        return _normalize_vt(r, "hash", file_hash)
    except http_requests.exceptions.Timeout:
        return {"source": "virustotal", "indicator_type": "hash", "indicator": file_hash, "found": False, "error": "VirusTotal request timed out."}
    except http_requests.exceptions.RequestException as exc:
        return {"source": "virustotal", "indicator_type": "hash", "indicator": file_hash, "found": False, "error": f"VirusTotal connection error: {str(exc)[:100]}"}


def _normalize_vt(response, indicator_type: str, indicator_value: str) -> dict:
    """Normalize a VirusTotal API response into a consistent dict."""
    result = {
        "source": "virustotal",
        "indicator_type": indicator_type,
        "indicator": indicator_value,
        "found": False,
        "error": None,
        "raw_status": response.status_code,
    }

    if response.status_code in (401, 403):
        result["error"] = "Invalid or missing VirusTotal API key. Check your key in backend/.env."
        return result
    if response.status_code == 429:
        result["error"] = "VirusTotal rate limit exceeded (Free tier: 4 requests/min, 500/day). Try again shortly."
        return result
    if response.status_code == 404:
        result["error"] = "No VirusTotal report found for this indicator."
        return result
    if response.status_code != 200:
        result["error"] = f"VirusTotal returned HTTP {response.status_code}."
        return result

    try:
        data = response.json().get("data", {})
        attrs = data.get("attributes", {})
    except Exception:
        result["error"] = "Failed to parse VirusTotal response."
        return result

    result["found"] = True

    # Last analysis stats
    stats = attrs.get("last_analysis_stats", {})
    result["stats"] = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
    }
    result["total_votes"] = attrs.get("total_votes", {})
    result["reputation"] = attrs.get("reputation", None)
    result["tags"] = attrs.get("tags", [])

    # Type-specific fields
    if indicator_type == "ip":
        result["country"] = attrs.get("country", "N/A")
        result["as_owner"] = attrs.get("as_owner", "N/A")
        result["asn"] = attrs.get("asn", None)
        result["network"] = attrs.get("network", None)
        result["whois"] = (attrs.get("whois", "") or "")[:500]
    elif indicator_type == "domain":
        result["registrar"] = attrs.get("registrar", "N/A")
        result["creation_date"] = attrs.get("creation_date", None)
        result["whois"] = (attrs.get("whois", "") or "")[:500]
        result["last_dns_records"] = attrs.get("last_dns_records", [])[:10]
        result["categories"] = attrs.get("categories", {})
    elif indicator_type == "url":
        result["url"] = attrs.get("url", indicator_value)
        result["title"] = attrs.get("title", "N/A")
        result["last_http_response_code"] = attrs.get("last_http_response_code", None)
        result["categories"] = attrs.get("categories", {})
    elif indicator_type == "hash":
        result["meaningful_name"] = attrs.get("meaningful_name", "N/A")
        result["type_description"] = attrs.get("type_description", "N/A")
        result["size"] = attrs.get("size", None)
        result["sha256"] = attrs.get("sha256", None)
        result["md5"] = attrs.get("md5", None)
        result["sha1"] = attrs.get("sha1", None)
        result["names"] = (attrs.get("names", []) or [])[:5]
        result["popular_threat_label"] = attrs.get(
            "popular_threat_classification", {}
        ).get("suggested_threat_label", None)

    return result


_CYBER_TRANSLATIONS = [
    # Spanish / Portuguese phrases commonly in threat feeds
    (re.compile(r"\bataques? de phishing\b", re.I), "phishing attack"),
    (re.compile(r"\bataques? de fuerza bruta\b", re.I), "brute-force attack"),
    (re.compile(r"\bactividad(es)? maliciosa(s)?\b", re.I), "malicious activity"),
    (re.compile(r"\bservidores? de comando y control\b", re.I), "command-and-control (C2) server"),
    (re.compile(r"\bservidores? c2\b", re.I), "C2 server"),
    (re.compile(r"\bdominios? maliciosos?\b", re.I), "malicious domain"),
    (re.compile(r"\bdominios? sospechosos?\b", re.I), "suspicious domain"),
    (re.compile(r"\bdirecciones? ip maliciosas?\b", re.I), "malicious IP address"),
    (re.compile(r"\binfecci[oó]n de malware\b", re.I), "malware infection"),
    (re.compile(r"\btr[aá]fico sospechoso\b", re.I), "suspicious traffic"),
    (re.compile(r"\bcampa[ñn]a de malware\b", re.I), "malware campaign"),
    (re.compile(r"\bcampa[ñn]a de ransomware\b", re.I), "ransomware campaign"),
    (re.compile(r"\bfraude bancario\b", re.I), "banking fraud"),
    (re.compile(r"\bservidor comprometido\b", re.I), "compromised server"),
    (re.compile(r"\brobo de credenciales\b", re.I), "credential theft"),
    (re.compile(r"\bvulnerabilidad explotada\b", re.I), "exploited vulnerability"),
    (re.compile(r"\bdenegaci[oó]n de servicio\b", re.I), "denial of service (DoS)"),
    (re.compile(r"\bamenaza detectada\b", re.I), "detected threat"),
    (re.compile(r"\bcomportamiento an[oó]malo\b", re.I), "anomalous behavior"),
    (re.compile(r"\bbloqueo de ip\b", re.I), "blocked IP"),
    (re.compile(r"\blista negra\b", re.I), "blocklist"),
    (re.compile(r"\bataque dirigido\b", re.I), "targeted attack"),
    (re.compile(r"\bescaneo de puertos\b", re.I), "port scanning"),
    (re.compile(r"\bfiltraci[oó]n de datos\b", re.I), "data exfiltration"),
    (re.compile(r"\bcorreo no deseado\b", re.I), "spam email"),
    (re.compile(r"\barchivos? infectados?\b", re.I), "infected file"),
    (re.compile(r"\bmuestra de malware\b", re.I), "malware sample"),
    (re.compile(r"\bamenazas? persistentes?\b", re.I), "persistent threat"),
    (re.compile(r"\bespionaje cibern[eé]tico\b", re.I), "cyber espionage"),
    (re.compile(r"\bsecuestro de datos\b", re.I), "ransomware data hijacking"),
    (re.compile(r"\bsuplantaci[oó]n de identidad\b", re.I), "identity spoofing / phishing"),
    (re.compile(r"\bdetectado en\b", re.I), "detected in"),
    (re.compile(r"\basociado a\b", re.I), "associated with"),
    (re.compile(r"\brelacionado con\b", re.I), "related to"),
    (re.compile(r"\butilizado por\b", re.I), "used by"),
    (re.compile(r"\borigen de\b", re.I), "origin of"),
    (re.compile(r"\bdestino de\b", re.I), "target of"),
]

def _normalize_to_english(text: str) -> str:
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in _CYBER_TRANSLATIONS:
        result = pattern.sub(replacement, result)
    return result


# ---------------------------------------------------------------------------
# AlienVault OTX helpers
# ---------------------------------------------------------------------------
def _otx_headers():
    headers = {"Accept": "application/json"}
    k = get_otx_api_key()
    if k and not _is_placeholder(k):
        headers["X-OTX-API-KEY"] = k
    return headers


def _otx_lookup(indicator_type: str, value: str) -> dict:
    type_map = {
        "ip": f"indicators/IPv4/{value}/general",
        "domain": f"indicators/domain/{value}/general",
        "url": f"indicators/url/{url_quote(value, safe='')}/general",
        "hash": f"indicators/file/{value}/general",
    }
    path = type_map.get(indicator_type)
    if not path:
        return {"source": "alienvault_otx", "error": "Unsupported indicator type."}

    result = {
        "source": "alienvault_otx",
        "indicator_type": indicator_type,
        "indicator": value,
        "found": False,
        "error": None,
    }

    try:
        r = http_requests.get(
            f"{OTX_BASE}/{path}", headers=_otx_headers(), timeout=REQUEST_TIMEOUT
        )
    except http_requests.exceptions.Timeout:
        result["error"] = "AlienVault OTX request timed out."
        return result
    except http_requests.exceptions.RequestException as exc:
        result["error"] = f"AlienVault OTX request failed: {str(exc)[:200]}"
        return result

    if r.status_code == 401 or r.status_code == 403:
        result["error"] = "Invalid or missing AlienVault OTX API key."
        result["raw_status"] = r.status_code
        return result
    if r.status_code == 429:
        result["error"] = "AlienVault OTX rate limit exceeded."
        result["raw_status"] = r.status_code
        return result
    if r.status_code == 404:
        result["error"] = "No AlienVault OTX report found for this indicator."
        result["raw_status"] = r.status_code
        return result
    if r.status_code != 200:
        result["error"] = f"AlienVault OTX returned HTTP {r.status_code}."
        result["raw_status"] = r.status_code
        return result

    try:
        data = r.json()
    except Exception:
        result["error"] = "Failed to parse AlienVault OTX response."
        return result

    result["found"] = True
    result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)

    pulses_raw = data.get("pulse_info", {}).get("pulses", [])
    result["pulses"] = [
        {
            "name": _normalize_to_english(p.get("name", "")),
            "description": _normalize_to_english(p.get("description", "") or "")[:250],
            "created": p.get("created", ""),
            "tags": [_normalize_to_english(t) for t in (p.get("tags", []) or [])[:10]],
            "adversary": _normalize_to_english(p.get("adversary", "")),
            "targeted_countries": (p.get("targeted_countries", []) or [])[:5],
            "attack_ids": [
                _normalize_to_english(a.get("display_name", "")) for a in (p.get("attack_ids", []) or [])[:5]
            ],
        }
        for p in pulses_raw[:10]
    ]

    # General section
    general = data.get("general", data)  # sometimes nested, sometimes flat
    result["reputation"] = general.get("reputation", None)
    result["country"] = (
        data.get("country_name") or data.get("country_code") or "N/A"
    )
    result["asn"] = data.get("asn", None)
    result["validation"] = data.get("validation", [])

    return result


# ---------------------------------------------------------------------------
# NVIDIA AI chatbot
# ---------------------------------------------------------------------------
def _nvidia_chat(user_message: str, report_context: str) -> dict:
    """Send a chat request to an NVIDIA-hosted model."""
    nvidia_key = get_nvidia_api_key()
    if not nvidia_key or _is_placeholder(nvidia_key):
        return {"error": "NVIDIA API key not configured in backend/.env. Add a key from build.nvidia.com.", "reply": None}

    system_prompt = (
        "You are ThreatIntel AI, an intelligent cybersecurity threat intelligence assistant communicating in simple, clear English.\n\n"
        "Core Instructions:\n"
        "1. English Only: Always answer in clear, simple English. If any threat pulses, descriptions, or report fields are in Spanish or other non-English languages, translate and explain them in plain English.\n"
        "2. Plain Language Explanations: Explain technical cybersecurity terms in simple words whenever they appear:\n"
        "   - ASN means the Network Owner / Internet Service Provider.\n"
        "   - File Hash means a unique digital fingerprint of a file (MD5/SHA256).\n"
        "   - Threat Pulse means a community security alert reported by researchers.\n"
        "   - Reputation means the community trust score.\n"
        "3. Clear Verdict: Clearly explain whether the indicator looks Malicious, Suspicious, Harmless, or Unknown based strictly on the live report findings.\n"
        "4. Evidence Rule: Never claim an indicator or website is safe without sufficient evidence. Explain that 0 detections or harmless votes only mean security engines have not flagged it yet.\n"
        "5. Accurate Reporting: Never invent whitelist status, vendor ratings, or HTTP response codes that do not exist in the report.\n"
        "6. Formatting: Use short, readable sentences, clear Markdown headings (###), bold text for key indicators, and bullet points."
    )

    messages = [
        {"role": "system", "content": system_prompt},
    ]

    if report_context:
        messages.append(
            {
                "role": "user",
                "content": f"Here is the current threat intelligence report context:\n\n{report_context}",
            }
        )
        messages.append(
            {
                "role": "assistant",
                "content": "I've reviewed the threat intelligence report. How can I help you analyze this data?",
            }
        )

    messages.append({"role": "user", "content": user_message})

    model_name = get_nvidia_model()
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
        "top_p": 0.9,
    }

    try:
        r = http_requests.post(
            NVIDIA_BASE,
            headers={
                "Authorization": f"Bearer {nvidia_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=60,
        )
    except http_requests.exceptions.Timeout:
        return {"error": "NVIDIA API request timed out (waited 60s). Please try again shortly.", "reply": None}
    except http_requests.exceptions.RequestException as exc:
        return {"error": f"NVIDIA API request failed: {str(exc)[:200]}", "reply": None}

    if r.status_code == 401 or r.status_code == 403:
        return {"error": "Invalid or missing NVIDIA API key in backend/.env. Ensure you use an API key from build.nvidia.com (starts with 'nvapi-').", "reply": None}
    if r.status_code == 410:
        return {"error": f"NVIDIA model '{payload['model']}' is no longer active. Set NVIDIA_MODEL=nvidia/llama-3.1-nemotron-70b-instruct in backend/.env.", "reply": None}
    if r.status_code == 429:
        return {"error": "NVIDIA API rate limit exceeded.", "reply": None}
    if r.status_code != 200:
        return {
            "error": f"NVIDIA API returned HTTP {r.status_code}.",
            "reply": None,
        }

    try:
        data = r.json()
        reply = data["choices"][0]["message"]["content"]
        return {"error": None, "reply": reply}
    except (KeyError, IndexError, Exception) as exc:
        return {"error": f"Failed to parse NVIDIA response: {str(exc)[:200]}", "reply": None}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    vt_key = get_vt_api_key()
    otx_key = get_otx_api_key()
    nv_key = get_nvidia_api_key()

    return jsonify(
        {
            "status": "ok",
            "service": "ThreatIntel AI Backend",
            "sources": {
                "virustotal": "configured" if (vt_key and not _is_placeholder(vt_key)) else "not configured",
                "alienvault_otx": "configured" if (otx_key and not _is_placeholder(otx_key)) else "not configured",
                "nvidia_ai": "configured" if (nv_key and not _is_placeholder(nv_key)) else "not configured",
            },
            "keys_present": {
                "virustotal": bool(vt_key),
                "alienvault_otx": bool(otx_key),
                "nvidia_ai": bool(nv_key),
            },
        }
    )


@app.route("/api/lookup", methods=["POST"])
def lookup():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    indicator = sanitize(body.get("indicator", ""))
    if not indicator:
        return jsonify({"error": "Missing 'indicator' field."}), 400

    # Detect or accept explicit type
    ind_type = body.get("type") or detect_indicator_type(indicator)
    if not ind_type or ind_type not in ("ip", "domain", "url", "hash"):
        return (
            jsonify(
                {
                    "error": "Could not determine indicator type. Supported: ip, domain, url, hash."
                }
            ),
            400,
        )

    # --- VirusTotal ---
    vt_result = None
    vt_k = get_vt_api_key()
    if vt_k and not _is_placeholder(vt_k):
        try:
            dispatch = {
                "ip": _vt_lookup_ip,
                "domain": _vt_lookup_domain,
                "url": _vt_lookup_url,
                "hash": _vt_lookup_hash,
            }
            vt_result = dispatch[ind_type](indicator)
        except http_requests.exceptions.Timeout:
            vt_result = {
                "source": "virustotal",
                "found": False,
                "error": "VirusTotal request timed out.",
            }
        except Exception as exc:
            vt_result = {
                "source": "virustotal",
                "found": False,
                "error": f"VirusTotal error: {str(exc)[:200]}",
            }
    else:
        vt_result = {
            "source": "virustotal",
            "found": False,
            "error": "VirusTotal API key not configured in backend/.env. Please replace the placeholder with your 64-character API key from virustotal.com.",
        }

    # --- AlienVault OTX ---
    otx_result = None
    try:
        otx_result = _otx_lookup(ind_type, indicator)
    except Exception as exc:
        otx_result = {
            "source": "alienvault_otx",
            "found": False,
            "error": f"AlienVault OTX error: {str(exc)[:200]}",
        }

    return jsonify(
        {
            "indicator": indicator,
            "type": ind_type,
            "virustotal": vt_result,
            "alienvault_otx": otx_result,
        }
    )


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    message = sanitize(body.get("message", ""))
    if not message:
        return jsonify({"error": "Missing 'message' field."}), 400

    context = body.get("context", "")
    if isinstance(context, dict):
        context = json.dumps(context, indent=2)
    context = str(context)[:8000]  # Limit context size

    result = _nvidia_chat(message, context)
    if result["error"]:
        return jsonify(result), 502
    return jsonify(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
