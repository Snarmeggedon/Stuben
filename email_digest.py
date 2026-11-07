"""Daily email digest: summarizes only mail vetted as safe."""
import re
from datetime import datetime
from pathlib import Path

from email.utils import parseaddr

from email_vetting import SAFE, SUSPICIOUS, JUNK, vet_messages

JOB_KEYWORDS = (
    'application', 'applied', 'interview', 'recruiter', 'recruiting', 'job', 'position', 'candidate',
    'offer letter', 'hiring', 'career', 'resume', 'assessment', 'next steps', 'talent', 'role at',
)
JOB_SENDERS = ('greenhouse', 'lever.co', 'workday', 'indeed', 'linkedin', 'icims', 'smartrecruiters',
               'ashbyhq', 'handshake', 'ziprecruiter', 'glassdoor', 'jobvite', 'taleo')
IMPORTANT_KEYWORDS = (
    'urgent', 'deadline', 'due', 'action required', 'expires', 'expiring', 'reminder', 'invoice',
    'payment', 'receipt', 'bill', 'appointment', 'confirm', 'security alert', 'password', 'tomorrow',
    'today', 'overdue', 'statement', 'delivery', 'shipped', 'meeting',
)


def categorize(message):
    sender = message.get('from', '').lower()
    text = f"{message.get('subject', '')} {message.get('snippet', '')}".lower()
    if any(s in sender for s in JOB_SENDERS) or any(re.search(rf'\b{re.escape(k)}', text) for k in JOB_KEYWORDS):
        return 'job'
    if any(re.search(rf'\b{re.escape(k)}', text) for k in IMPORTANT_KEYWORDS):
        return 'important'
    return 'fyi'


def build_digest(messages, now=None):
    now = now or datetime.now()
    vetted = vet_messages(messages)
    groups = {'job': [], 'important': [], 'fyi': []}
    counts = {SAFE: 0, SUSPICIOUS: 0, JUNK: 0}
    for msg, verdict in vetted:
        counts[verdict['verdict']] += 1
        if verdict['verdict'] == SAFE:
            groups[categorize(msg)].append(msg)
    return {'generated': now, 'total': len(messages), 'counts': counts, 'groups': groups}


def _line(msg):
    name, addr = parseaddr(msg.get('from', ''))
    who = (name or addr or 'Unknown').replace('|', '/')
    subject = (msg.get('subject') or '(no subject)').replace('\n', ' ')
    snippet = (msg.get('snippet') or '').strip().replace('\n', ' ')
    if len(snippet) > 140:
        snippet = snippet[:137] + '...'
    out = f'- **{subject}** - {who}'
    if snippet:
        out += f'\n  > {snippet}'
    return out


def render_markdown(digest):
    d, g, c = digest['generated'], digest['groups'], digest['counts']
    lines = [
        f"# Email Digest - {d.strftime('%A, %B %d, %Y %I:%M %p')}",
        '',
        f"{digest['total']} message(s) reviewed: {c[SAFE]} safe, "
        f"{c[SUSPICIOUS]} suspicious, {c[JUNK]} junk.",
        '',
    ]
    for key, title in (('job', 'Job Updates'), ('important', 'Important / Time-Sensitive'), ('fyi', 'FYI')):
        lines.append(f'## {title} ({len(g[key])})')
        lines.extend([_line(m) for m in g[key]] or ['_Nothing new._'])
        lines.append('')
    lines += [
        '## Filtered',
        f"- {c[JUNK]} junk item(s) and {c[SUSPICIOUS]} suspicious item(s) were filtered out "
        'and their bodies were never opened.',
        '',
    ]
    return '\n'.join(lines)


def write_digest(messages, output_path=None, now=None):
    digest = build_digest(messages, now)
    path = Path(output_path) if output_path else Path(__file__).resolve().parent / 'digests' / \
        f"email_digest_{digest['generated'].strftime('%Y-%m-%d')}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(digest), encoding='utf-8')
    return path, digest
