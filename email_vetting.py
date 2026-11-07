"""Metadata-only email vetting. Never reads message bodies."""
import re
from email.utils import parseaddr

SAFE, SUSPICIOUS, JUNK = 'safe', 'suspicious', 'junk'

RISKY_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.ps1',
    '.msi', '.jar', '.lnk', '.iso', '.img', '.hta', '.reg', '.dll', '.docm', '.xlsm', '.pptm',
}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.gz', '.ace'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at'}
SUSPICIOUS_TLDS = {'.zip', '.mov', '.top', '.xyz', '.click', '.work', '.gq', '.tk', '.ml', '.cf', '.ru', '.icu'}

PHISHING_PHRASES = (
    'verify your account', 'account suspended', 'account has been suspended', 'confirm your password',
    'update your payment', 'unusual sign-in', 'unusual activity', 'urgent action required',
    'click here immediately', 'your account will be closed', 'security alert: action required',
    'gift card', 'wire transfer', 'you have won', 'claim your prize', 'act now', 'limited time offer',
    'password expires', 'invoice attached', 'suspended due to', 'confirm your identity',
)
JUNK_PHRASES = (
    'unsubscribe', 'view in browser', 'special offer', '% off', 'flash sale', 'free shipping',
    'newsletter', 'deal of the day', 'buy now', 'sale ends',
)

BRANDS = {
    'paypal': {'paypal.com'}, 'microsoft': {'microsoft.com', 'outlook.com', 'live.com'},
    'google': {'google.com', 'gmail.com', 'accounts.google.com'}, 'apple': {'apple.com', 'icloud.com'},
    'amazon': {'amazon.com'}, 'netflix': {'netflix.com'}, 'bank of america': {'bankofamerica.com'},
    'wells fargo': {'wellsfargo.com'}, 'chase': {'chase.com'}, 'linkedin': {'linkedin.com'},
    'docusign': {'docusign.com', 'docusign.net'}, 'irs': {'irs.gov'},
}

URL_RE = re.compile(r'https?://[^\s<>"\')]+', re.I)
IP_HOST_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _first(headers, name):
    values = headers.get(name.lower()) or []
    return values[0] if values else ''


def _domain(address):
    addr = parseaddr(address)[1].lower()
    return addr.rsplit('@', 1)[1] if '@' in addr else ''


def _same_org(a, b):
    if not a or not b:
        return True
    ra, rb = '.'.join(a.split('.')[-2:]), '.'.join(b.split('.')[-2:])
    return ra == rb


def _auth_result(headers, mechanism):
    blob = ' '.join(
        (headers.get('authentication-results') or []) + (headers.get('received-spf') or [])
    ).lower()
    m = re.search(rf'\b{mechanism}\s*=\s*(\w+)', blob)
    if m:
        return m.group(1)
    if mechanism == 'spf':
        m = re.match(r'\s*(pass|fail|softfail|neutral|none)', _first(headers, 'received-spf').lower())
        return m.group(1) if m else None
    return None


def vet_message(message):
    """Score one message dict (as produced by GmailIntegration.scan_messages)."""
    headers = message.get('headers') or {}
    sender = message.get('from', '')
    subject = message.get('subject', '') or ''
    snippet = message.get('snippet', '') or ''
    text = f'{subject} {snippet}'.lower()
    from_domain = _domain(sender)
    display = parseaddr(sender)[0].lower()

    score, junk_score, reasons = 0, 0, []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    for mech in ('spf', 'dkim', 'dmarc'):
        res = _auth_result(headers, mech)
        if res in ('fail', 'permerror'):
            add(4, f'{mech.upper()} failed')
        elif res in ('softfail', 'temperror'):
            add(2, f'{mech.upper()} {res}')
    if not any(_auth_result(headers, m) for m in ('spf', 'dkim', 'dmarc')):
        add(1, 'No authentication results in headers')

    for hdr in ('reply-to', 'return-path'):
        other = _domain(_first(headers, hdr))
        if other and from_domain and not _same_org(from_domain, other):
            add(3 if hdr == 'reply-to' else 2, f'{hdr} domain ({other}) differs from sender ({from_domain})')

    for brand, domains in BRANDS.items():
        if brand in display and from_domain and not any(_same_org(from_domain, d) for d in domains):
            add(5, f'Display name claims "{brand}" but sender domain is {from_domain}')
            break
    if re.search(r'[\w.-]+@[\w.-]+', display) and _domain(display) and not _same_org(_domain(display), from_domain):
        add(4, 'Display name contains a different email address')
    if from_domain.startswith('xn--') or '.xn--' in from_domain:
        add(3, 'Punycode sender domain')
    if any(from_domain.endswith(t) for t in SUSPICIOUS_TLDS):
        add(2, f'Sender uses high-risk TLD ({from_domain})')
    label = from_domain.split('.')[0] if from_domain else ''
    normalized = label.replace('0', 'o').replace('1', 'l')
    if normalized != label and any(b.replace(' ', '') in normalized for b in BRANDS):
        add(3, 'Possible look-alike (digit-substitution) sender domain')

    for url in URL_RE.findall(snippet):
        host = re.sub(r'^https?://', '', url, flags=re.I).split('/')[0].split(':')[0].lower()
        if IP_HOST_RE.match(host):
            add(4, f'Link to raw IP address ({host})')
        elif host in SHORTENERS:
            add(2, f'URL shortener link ({host})')
        elif any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            add(2, f'Link to high-risk TLD ({host})')
        elif '@' in url.split('//', 1)[-1].split('/')[0]:
            add(3, 'Link contains embedded credentials/@ trick')

    for phrase in PHISHING_PHRASES:
        if phrase in text:
            add(2, f'Phishing phrase: "{phrase}"')
    if re.search(r'\b(urgent|immediately|final notice|within 24 hours)\b', text) and score:
        add(1, 'Urgency language')

    for att in message.get('attachments') or []:
        name = (att.get('filename') or '').lower()
        ext = '.' + name.rsplit('.', 1)[1] if '.' in name else ''
        if re.search(r'\.\w{2,4}\.(exe|scr|bat|js|vbs|cmd|com)$', name):
            add(6, f'Double-extension attachment: {att.get("filename")}')
        elif ext in RISKY_EXTENSIONS:
            add(5, f'Risky attachment type: {att.get("filename")}')
        elif ext in ARCHIVE_EXTENSIONS:
            add(2, f'Archive attachment: {att.get("filename")}')

    marketing = [p for p in JUNK_PHRASES if p in text]
    if _first(headers, 'list-unsubscribe'):
        junk_score += 1
    junk_score += len(marketing)
    labels = set(message.get('labels') or [])
    if labels & {'SPAM'}:
        score += 4
        reasons.append('Gmail marked as spam')
    if labels & {'CATEGORY_PROMOTIONS', 'CATEGORY_SOCIAL'}:
        junk_score += 2
    if marketing:
        reasons.append('Marketing phrases: ' + ', '.join(marketing[:3]))

    if score >= 5:
        verdict = SUSPICIOUS
    elif score >= 3 and junk_score >= 2:
        verdict = SUSPICIOUS
    elif junk_score >= 3 or (labels & {'CATEGORY_PROMOTIONS'} and score < 3):
        verdict = JUNK
    elif score >= 3:
        verdict = SUSPICIOUS
    else:
        verdict = SAFE

    return {
        'id': message.get('id'),
        'verdict': verdict,
        'score': score,
        'junk_score': junk_score,
        'reasons': reasons,
        'may_open_body': verdict == SAFE,
    }


def vet_messages(messages):
    """Return [(message, verdict_dict)] for all messages."""
    return [(m, vet_message(m)) for m in messages]
