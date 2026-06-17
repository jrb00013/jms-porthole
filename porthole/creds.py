"""
Common default credential pairs frequently found on network devices, IoT, and servers.
Used with the spray command for authorized credential auditing.
"""

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("user", "user"),
    ("user", "password"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("guest", "guest"),
    ("test", "test"),
    ("support", "support"),
    ("service", "service"),
    ("operator", "operator"),
    ("administrator", "administrator"),
]

WORDLIST_USERNAMES = [r[0] for r in DEFAULT_CREDENTIALS]
WORDLIST_PASSWORDS = list(dict.fromkeys(r[1] for r in DEFAULT_CREDENTIALS))


def load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
