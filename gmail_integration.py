from pathlib import Path


class GmailIntegration:
    DEFAULT_SEARCH_DIRS = (
        Path.home() / 'Downloads',
        Path.home() / 'Desktop',
        Path.home() / 'Documents',
        Path.home() / 'OneDrive' / 'Desktop',
        Path.home() / 'OneDrive' / 'Documents',
        Path(__file__).resolve().parent,
    )
    FILE_PATTERNS = (
        'gmail_credentials.json',
        'client_secret*.json',
        '*.apps.googleusercontent.com.json',
    )

    @classmethod
    def discover_credentials_candidates(cls):
        candidates = []
        seen = set()

        for directory in cls.DEFAULT_SEARCH_DIRS:
            if not directory.exists():
                continue

            for pattern in cls.FILE_PATTERNS:
                for path in directory.glob(pattern):
                    if path.is_file():
                        resolved = str(path.resolve())
                        if resolved not in seen:
                            seen.add(resolved)
                            candidates.append(path.resolve())

        return candidates

    @classmethod
    def is_oauth_credentials_file(cls, path):
        try:
            text = Path(path).read_text(encoding='utf-8', errors='ignore')
            required_fields = ('client_id', 'auth_uri', 'token_uri')
            return all(field in text for field in required_fields)
        except Exception:
            return False

    def __init__(self, credentials_path=None, token_path=None):
        base = Path(__file__).resolve().parent
        self.credentials_path = Path(credentials_path) if credentials_path else base / 'gmail_credentials.json'
        self.token_path = Path(token_path) if token_path else base / 'gmail_token.json'

    def authenticate(self):
        path = self.credentials_path
        if not path.exists():
            raise RuntimeError(
                'No Google OAuth credentials JSON found. Download it and place it in Downloads, Desktop, Documents, or the Stuben folder.'
            )
        return str(self.token_path)

    def scan_messages(self, query='in:inbox newer_than:7d', limit=10, include_attachments=True):
        return {
            'query': query,
            'limit': limit,
            'message_count': 0,
            'messages': [],
            'note': 'This build is in offline-safe mode. Gmail auth requires a real Google OAuth client to complete.'
        }
