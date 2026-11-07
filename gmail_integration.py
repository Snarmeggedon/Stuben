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

    SCOPES = ('https://www.googleapis.com/auth/gmail.readonly',)
    METADATA_HEADERS = (
        'From', 'Reply-To', 'Return-Path', 'To', 'Subject', 'Date', 'Message-ID',
        'Authentication-Results', 'Received-SPF', 'DKIM-Signature', 'ARC-Authentication-Results',
        'List-Unsubscribe', 'X-Mailer', 'Content-Type',
    )

    def _load_token(self):
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request

        if not self.token_path.exists():
            return None
        creds = Credentials.from_authorized_user_file(str(self.token_path), list(self.SCOPES))
        if creds.valid:
            return creds
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            self.token_path.write_text(creds.to_json(), encoding='utf-8')
            return creds
        return None

    def authenticate(self, interactive=False):
        """Return Google credentials (gmail.readonly only).

        Non-interactive by default: raises if no usable token exists. Pass
        interactive=True (or run `py agent.py gmail-auth`) for one-time browser consent.
        """
        if not self.credentials_path.exists():
            raise RuntimeError(
                'No Google OAuth credentials JSON found. Place it at gmail_credentials.json in the Stuben folder.'
            )
        creds = self._load_token()
        if creds:
            return creds
        if not interactive:
            raise RuntimeError('No valid Gmail token. Run once: py agent.py gmail-auth')

        from google_auth_oauthlib.flow import InstalledAppFlow

        flow = InstalledAppFlow.from_client_secrets_file(str(self.credentials_path), list(self.SCOPES))
        creds = flow.run_local_server(port=0)
        self.token_path.write_text(creds.to_json(), encoding='utf-8')
        return creds

    def _service(self):
        from googleapiclient.discovery import build

        return build('gmail', 'v1', credentials=self.authenticate(), cache_discovery=False)

    @staticmethod
    def _collect_attachments(part, out):
        filename = part.get('filename')
        if filename:
            out.append({'filename': filename, 'mime_type': part.get('mimeType', '')})
        for sub in part.get('parts') or []:
            GmailIntegration._collect_attachments(sub, out)

    def _attachment_info(self, service, msg_id):
        # Structure only: filenames/MIME types are read; body data is never decoded.
        full = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        out = []
        self._collect_attachments(full.get('payload') or {}, out)
        return out

    def scan_messages(self, query='in:inbox newer_than:1d', limit=50, include_attachments=True):
        service = self._service()
        listing = service.users().messages().list(userId='me', q=query, maxResults=limit).execute()
        messages = []
        for ref in listing.get('messages', []):
            msg = service.users().messages().get(
                userId='me', id=ref['id'], format='metadata',
                metadataHeaders=list(self.METADATA_HEADERS),
            ).execute()
            headers = {}
            for h in (msg.get('payload') or {}).get('headers', []):
                headers.setdefault(h['name'].lower(), []).append(h['value'])
            ctype = ' '.join(headers.get('content-type', [])).lower()
            attachments = []
            if include_attachments and ('multipart/mixed' in ctype or 'multipart/related' in ctype or not ctype):
                attachments = self._attachment_info(service, ref['id'])
            messages.append({
                'id': msg['id'],
                'thread_id': msg.get('threadId'),
                'from': (headers.get('from') or [''])[0],
                'subject': (headers.get('subject') or [''])[0],
                'date': (headers.get('date') or [''])[0],
                'snippet': msg.get('snippet', ''),
                'labels': msg.get('labelIds', []),
                'headers': headers,
                'attachments': attachments,
            })
        return {'query': query, 'limit': limit, 'message_count': len(messages), 'messages': messages}
