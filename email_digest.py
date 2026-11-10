"""Daily email digest: summarizes only mail vetted as safe."""
import html
import json
import re
from datetime import datetime
from pathlib import Path

from email.utils import parseaddr

from appointments import build_ics, detect_appointment, merge_store
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


STATUS_KEYWORDS = (
    'thank you for applying', 'thanks for applying', 'application has been received', 'received your application',
    'application for', 'your application', 'interview', 'offer', 'next steps', 'assessment', 'not moving forward',
    'unfortunately', 'regret', 'schedule a call', 'recruiter', 'background check', 'we would like to',
)
ALERT_SENDERS = ('jobalert', 'job alert', 'jobright', 'apt job', 'talenthop', 'ziprecruiter')


def is_job_status(message):
    text = f"{message.get('subject', '')} {message.get('snippet', '')}".lower()
    sender = message.get('from', '').lower()
    if 'jobs similar' in text or 'new jobs' in text or 'is hiring' in text or any(a in sender for a in ALERT_SENDERS):
        return False
    return any(k in text for k in STATUS_KEYWORDS)


def build_digest(messages, now=None):
    now = now or datetime.now()
    vetted = vet_messages(messages)
    groups = {'job': [], 'job_alerts': [], 'important': [], 'fyi': []}
    counts = {SAFE: 0, SUSPICIOUS: 0, JUNK: 0}
    quarantined = []
    appointments = []
    for msg, verdict in vetted:
        counts[verdict['verdict']] += 1
        if verdict['verdict'] == SAFE:
            appt = detect_appointment(msg, now.date())
            if appt:
                appointments.append(appt)
            cat = categorize(msg)
            if cat == 'job' and not is_job_status(msg):
                cat = 'job_alerts'
            groups[cat].append(msg)
        else:
            quarantined.append({
                'id': msg.get('id'), 'verdict': verdict['verdict'], 'score': verdict['score'],
                'from': msg.get('from', ''), 'subject': msg.get('subject', ''),
                'date': msg.get('date', ''), 'reasons': verdict['reasons'],
            })
    return {'generated': now, 'total': len(messages), 'counts': counts, 'groups': groups,
            'quarantined': quarantined, 'appointments': appointments, 'new_appointments': appointments}


def _line(msg):
    name, addr = parseaddr(msg.get('from', ''))
    who = (name or addr or 'Unknown').replace('|', '/')
    subject = (msg.get('subject') or '(no subject)').replace('\n', ' ')
    snippet = html.unescape(msg.get('snippet') or '')
    snippet = re.sub(r'[\u200b-\u200f\u034f\u2060\ufeff\u00ad\u202f\xa0\s]+', ' ', snippet).strip()
    subject = html.unescape(subject)
    if len(snippet) > 140:
        snippet = snippet[:137] + '...'
    out = f'- **{subject}** - {who}'
    if snippet:
        out += f'\n  > {snippet}'
    return out


def _appt_line(appt, is_new):
    when = appt['date'] or 'date unknown'
    if appt.get('time'):
        when += f" at {datetime.strptime(appt['time'], '%H:%M').strftime('%I:%M %p').lstrip('0')}"
    tag = ' **(new - want a reminder?)**' if is_new else ''
    note = f" - {appt['note']}" if appt.get('note') else ''
    return f"- **{appt['title']}** - {when}{note}{tag}"


def render_markdown(digest):
    d, g, c = digest['generated'], digest['groups'], digest['counts']
    lines = [
        f"# Email Digest - {d.strftime('%A, %B %d, %Y %I:%M %p')}",
        '',
        f"{digest['total']} message(s) reviewed: {c[SAFE]} safe, "
        f"{c[SUSPICIOUS]} suspicious, {c[JUNK]} junk.",
        '',
    ]
    appts = digest.get('appointments') or []
    new_keys = {a['id'] for a in digest.get('new_appointments') or []}
    lines.append(f'## Appointments & Reminders ({len(appts)})')
    if appts:
        lines.extend(_appt_line(a, a.get('id') in new_keys) for a in appts)
        lines.append('_Reminder requests: tell me which to set, or import the .ics file next to this digest '
                     '(it adds alerts 1 day and 1 hour before)._')
    else:
        lines.append('_No appointments found._')
    lines.append('')
    for key, title in (('job', 'Job Application Updates'), ('important', 'Important / Time-Sensitive'),
                       ('job_alerts', 'Job Alerts & New Listings'), ('fyi', 'FYI')):
        lines.append(f'## {title} ({len(g[key])})')
        lines.extend([_line(m) for m in g[key]] or ['_Nothing new._'])
        lines.append('')
    lines += [
        '## Quarantined',
        f"- {c[JUNK]} junk item(s) and {c[SUSPICIOUS]} suspicious item(s) were filtered out "
        'and their bodies were never opened. Details are in the quarantine report.',
        '',
    ]
    return '\n'.join(lines)


def write_quarantine(digest, directory=None):
    """Local quarantine report (Gmail access is read-only, so mail itself is not moved)."""
    directory = Path(directory) if directory else Path(__file__).resolve().parent / 'quarantine'
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"email_quarantine_{digest['generated'].strftime('%Y-%m-%d')}.json"
    path.write_text(json.dumps(digest['quarantined'], indent=2), encoding='utf-8')
    return path


def write_digest(messages, output_path=None, now=None, quarantine_dir=None, appointments_store=None):
    digest = build_digest(messages, now)
    base = Path(__file__).resolve().parent
    path = Path(output_path) if output_path else base / 'digests' / \
        f"email_digest_{digest['generated'].strftime('%Y-%m-%d')}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    store = appointments_store if appointments_store is not None else (
        base / 'appointments.json' if output_path is None else path.with_name('appointments.json'))
    upcoming, new_keys = merge_store(store, digest['appointments'], digest['generated'].date())
    undated = [a for a in digest['appointments'] if not a.get('date')]
    digest['new_appointments'] = [a for a in digest['appointments'] if a.get('date') and
                                  f"{a['title'].lower()}|{a['date']}|{a['time']}" in new_keys] + undated
    digest['appointments'] = upcoming + undated
    path.write_text(render_markdown(digest), encoding='utf-8')
    if upcoming:
        path.with_suffix('.ics').write_text(build_ics(upcoming, digest['generated']), encoding='utf-8')
    if quarantine_dir is not None or output_path is None:
        write_quarantine(digest, quarantine_dir)
    return path, digest
