import os

# Current live client version as of 2026-09-16 (OB55 launch day).
# OB53 and other odd versions are rejected by loginbp with "SignError1".
# Allow override without code push (e.g. Vercel env var) for fast rotation
# on the next OB release.
RELEASEVERSION = os.environ.get("FF_RELEASE_VERSION", "OB55")
DEBUG = os.environ.get("FF_DEBUG", "True").lower() in ("1", "true", "yes")
