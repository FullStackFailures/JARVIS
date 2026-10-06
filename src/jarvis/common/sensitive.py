"""Names that mark credential/secret stores (shared by policy scopes and filesystem search)."""

from __future__ import annotations

# Directory/file *names* that mark credential or secret stores, on any platform.
SENSITIVE_NAMES = frozenset(
    {
        ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".password-store", ".netrc", ".git-credentials",
        ".docker", "id_rsa", "id_ed25519", "id_ecdsa", "shadow", "gshadow", "sudoers", "ntuser.dat",
        "login data", "key3.db", "key4.db", "logins.json", ".gcloud",
    }
)
