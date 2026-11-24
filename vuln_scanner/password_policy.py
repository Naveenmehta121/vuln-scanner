"""
Password-policy checker — LOCAL CONFIG CHECK ONLY.

This reads a JSON file describing a site's password rules and judges
whether those rules are strong enough. It NEVER:
  * tries passwords against a login,
  * reads real user passwords or hashes,
  * brute-forces anything.

Expected JSON format (see tests/weak_policy.json for an example):
    {
      "min_length": 8,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digit": true,
      "require_special": true,
      "max_age_days": 90,
      "lockout_after_failed_attempts": 5
    }

Missing keys are treated as "rule not enforced" — the safest assumption.
"""

import json

# A password shorter than this is guessable no matter what else you require.
MIN_RECOMMENDED_LENGTH = 12


def check_password_policy(config_path: str) -> list:
    """Read a password-policy JSON file and return one finding per weakness."""
    try:
        with open(config_path, encoding="utf-8") as f:
            policy = json.load(f)
    except FileNotFoundError:
        return [{
            "check": "password-policy",
            "severity": "Medium",
            "title": "Password policy file not found",
            "detail": f"Could not read {config_path}.",
            "fix": "Pass a valid policy JSON file with --config, "
                   "or create one from the example in tests/weak_policy.json.",
        }]
    except json.JSONDecodeError as exc:
        return [{
            "check": "password-policy",
            "severity": "Medium",
            "title": "Password policy file is not valid JSON",
            "detail": str(exc),
            "fix": "Fix the JSON syntax in the policy file and re-run.",
        }]

    findings = []

    # --- length -----------------------------------------------------------
    min_len = policy.get("min_length", 0)
    if min_len < 8:
        findings.append({
            "check": "password-policy",
            "severity": "High",
            "title": f"Minimum password length is only {min_len} characters",
            "detail": "Short passwords fall to brute force / dictionary "
                      "attacks in minutes.",
            "fix": f"Require at least {MIN_RECOMMENDED_LENGTH} characters.",
        })
    elif min_len < MIN_RECOMMENDED_LENGTH:
        findings.append({
            "check": "password-policy",
            "severity": "Medium",
            "title": f"Minimum password length is {min_len} (below recommended {MIN_RECOMMENDED_LENGTH})",
            "detail": "Longer passwords are the single biggest defence "
                      "against guessing attacks.",
            "fix": f"Raise the minimum length to {MIN_RECOMMENDED_LENGTH}.",
        })

    # --- character variety -------------------------------------------------
    for key, label in [
        ("require_uppercase", "uppercase letters (A-Z)"),
        ("require_lowercase", "lowercase letters (a-z)"),
        ("require_digit", "digits (0-9)"),
        ("require_special", "special characters (!@#$…)"),
    ]:
        if not policy.get(key, False):
            findings.append({
                "check": "password-policy",
                "severity": "Low",
                "title": f"Password policy does not require {label}",
                "detail": "Fewer character types means a smaller search "
                          "space for an attacker.",
                "fix": f"Enable the '{key}' rule in your password policy.",
            })

    # --- rotation ----------------------------------------------------------
    max_age = policy.get("max_age_days")
    if max_age is None or max_age > 180:
        findings.append({
            "check": "password-policy",
            "severity": "Low",
            "title": "Passwords never expire (or expire after > 180 days)",
            "detail": "A leaked password stays useful forever if it is "
                      "never rotated.",
            "fix": "Set max_age_days to 90 and encourage a password manager.",
        })

    # --- lockout -----------------------------------------------------------
    lockout = policy.get("lockout_after_failed_attempts")
    if lockout is None or lockout <= 0 or lockout > 10:
        findings.append({
            "check": "password-policy",
            "severity": "Medium",
            "title": "No account lockout after failed logins (or threshold too high)",
            "detail": "Without lockout, an attacker can guess passwords "
                      "indefinitely.",
            "fix": "Lock accounts (or add CAPTCHA / delay) after 5 failed "
                   "attempts.",
        })

    return findings
