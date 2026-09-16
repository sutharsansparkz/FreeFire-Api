import os

# Current live client version as of 2026-09-16 (OB55 launch day).
# Allow override without code push (e.g. Vercel env var) for fast rotation
# on the next OB release.
RELEASEVERSION = os.environ.get("FF_RELEASE_VERSION", "OB55")
DEBUG = os.environ.get("FF_DEBUG", "True").lower() in ("1", "true", "yes")

# Ordered fallback chain tried by MajorLogin. During OB transition windows
# Garena's pools can reject the newest version (e.g. HTTP 400 "SignError1")
# while an older pool still answers, or vice versa. First response that
# contains a token wins. Override with FF_RELEASE_VERSIONS="OB55,OB54".
_raw_versions = os.environ.get("FF_RELEASE_VERSIONS", "").strip()
if _raw_versions:
    RELEASEVERSIONS = [v.strip() for v in _raw_versions.split(",") if v.strip()]
else:
    RELEASEVERSIONS = [RELEASEVERSION]
    if "OB54" not in RELEASEVERSIONS:
        RELEASEVERSIONS.append("OB54")
    if not RELEASEVERSIONS:
        RELEASEVERSIONS = ["OB55", "OB54"]
