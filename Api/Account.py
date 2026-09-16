import re
from typing import Optional

import requests
import Proto.compiled.MajorLogin_pb2
from Utilities.until import encode_protobuf, decode_protobuf
import json
from Configuration.APIConfiguration import RELEASEVERSIONS, DEBUG


def get_garena_token(uid, password):
    """
    Get Garena token using uid and password
    
    Args:
        uid (str): User ID
        password (str): Password
    
    Returns:
        dict: JSON response from the API
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"

    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }

    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }

    try:
        response = requests.post(url, data=payload, headers=headers)
        response.raise_for_status()
        if DEBUG:
            print("[oauth/guest/token/grant] Response(raw):", response.content, "\n")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        return None



def extract_login_reason(raw: bytes) -> Optional[str]:
    """Best-effort extraction of a human-readable ban/queue reason from a
    MajorLogin protobuf payload.

    The compiled LoginQueueInfo proto is outdated (field 4 changed from
    bool to a string reason such as "Protection Bypass" /
    "Exploiting loopholes"), so the generated decoder silently drops it.
    Parse length-delimited fields directly instead of regexing raw bytes
    (regex greedily swallows the following field tag, e.g. trailing 'z').
    """
    def _read_varint(buf: bytes, pos: int):
        result = 0
        shift = 0
        consumed = 0
        while True:
            if pos + consumed >= len(buf):
                raise ValueError("truncated varint")
            byte = buf[pos + consumed]
            consumed += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        return result, consumed

    def _len_delimited_strings(buf: bytes):
        out = []
        pos = 0
        while pos < len(buf):
            try:
                key, n = _read_varint(buf, pos)
            except ValueError:
                break
            pos += n
            wire = key & 7
            if wire == 2:
                try:
                    length, n = _read_varint(buf, pos)
                except ValueError:
                    break
                pos += n
                blob = buf[pos:pos + length]
                pos += length
                try:
                    text = blob.decode('utf-8')
                    if len(text) >= 4 and all(c.isprintable() or c == ' ' for c in text):
                        out.append(text.strip())
                except UnicodeDecodeError:
                    pass
                # Recurse into nested messages (queueInfo is field 13).
                out.extend(_len_delimited_strings(blob))
            elif wire == 0:
                try:
                    _, n = _read_varint(buf, pos)
                    pos += n
                except ValueError:
                    break
            elif wire == 1:
                pos += 8
            elif wire == 5:
                pos += 4
            else:
                break
        return out

    try:
        candidates = [s for s in _len_delimited_strings(raw) if s]
        if candidates:
            # Prefer the longest meaningful server string.
            return max(candidates, key=len)
    except Exception:
        pass
    try:
        matches = re.findall(rb'[A-Za-z0-9][A-Za-z0-9 ]{3,}', raw)
        cleaned = [m.decode('utf-8', 'ignore').strip() for m in matches]
        cleaned = [c for c in cleaned if c]
        if cleaned:
            return max(cleaned, key=len)
    except Exception:
        pass
    return None


def get_major_login(logintoken, openid):
    """
    Perform major login with the provided credentials

    Tries each configured ReleaseVersion (see RELEASEVERSIONS) against the
    known loginbp hosts in order. The first response containing 'token' +
    'serverUrl' wins (returned with '_version' noting which version worked).
    If nothing yields a token, returns an aggregate dict with '_attempts'
    plus the most informative failure detail ('_reason' for queue/ban
    notices, else '_raw_error' for plain-text rejections like "SignError1").
    Returns False only when every attempt failed at transport level.

    Args:
        logintoken (str): The login token
        openid (str): The open ID

    Returns:
        dict | False: JSON response from the login API
    """
    # Create encrypted payload
    encrypted_payload = encode_protobuf({
        "openid": openid,
        "logintoken": logintoken,
        "platform": "4",
    }, Proto.compiled.MajorLogin_pb2.request())

    # API endpoints (canonical first, fallback second)
    urls = [
        "https://loginbp.ggblueshark.com/MajorLogin",
        "https://loginbp.ggpolarbear.com/MajorLogin",
    ]

    # Base headers (note: exactly one Content-Type; binary payload requires
    # application/octet-stream, NOT x-www-form-urlencoded)
    base_headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; A063 Build/TKQ1.221220.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': "Bearer",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
    }

    attempts = []
    best_detail = None  # most informative failure (prefer queue/ban reasons)
    for version in RELEASEVERSIONS:
        headers = dict(base_headers)
        headers['ReleaseVersion'] = version
        for url in urls:
            try:
                response = requests.post(url, data=encrypted_payload, headers=headers, timeout=15)
            except requests.exceptions.RequestException as e:
                print(f"[MajorLogin] Transport error ({url} {version}): {e}")
                attempts.append(f"{version}@{url}: transport error {e}")
                continue
            if DEBUG:
                print(f"[MajorLogin] {url} [{version}] HTTP {response.status_code} Response(raw):", response.content, "\n")
            content = response.content or b""
            # Non-200 responses are plain-text/HTML rejections (e.g. "SignError1",
            # 503 routing pages) — never protobuf. Surface them directly.
            if response.status_code != 200:
                try:
                    text = content.decode('utf-8', 'ignore').strip() or response.text.strip()
                except Exception:
                    text = response.text.strip()
                detail = {
                    "_raw_error": text[:500],
                    "_http_status": response.status_code,
                    "_host": url,
                    "_version": version,
                }
                attempts.append(f"{version}@{url}: HTTP {response.status_code} {text[:80]}")
                if best_detail is None:
                    best_detail = detail
                # SignError means this version is rejected: try the next
                # version, but a 5xx/503 (routing) is worth retrying on the
                # fallback host first.
                if response.status_code in (502, 503, 504):
                    continue
                break
            try:
                # Decode and return the response as JSON
                message = decode_protobuf(content, Proto.compiled.MajorLogin_pb2.response)
                if isinstance(message, dict):
                    message["_http_status"] = response.status_code
                    message["_host"] = url
                    message["_version"] = version
                    reason = extract_login_reason(content)
                    if reason:
                        message["_reason"] = reason
                if isinstance(message, dict) and message.get("token"):
                    return message
                attempts.append(
                    f"{version}@{url}: no token"
                    + (f" ({message.get('_reason')})" if isinstance(message, dict) and message.get("_reason") else "")
                )
                if isinstance(message, dict) and (message.get("_reason") or message.get("queueInfo") or message.get("blacklist")):
                    best_detail = message
                elif best_detail is None:
                    best_detail = message if isinstance(message, dict) else None
            except Exception:
                print("[MajorLogin] Error:", response.text)
                detail = {
                    "_raw_error": response.text.strip()[:500],
                    "_http_status": response.status_code,
                    "_host": url,
                    "_version": version,
                }
                attempts.append(f"{version}@{url}: decode error {response.text.strip()[:80]}")
                if best_detail is None:
                    best_detail = detail
    if best_detail is None:
        return False
    if isinstance(best_detail, dict):
        best_detail = dict(best_detail)
        best_detail["_attempts"] = attempts
    return best_detail