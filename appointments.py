"""Detect appointments in vetted-safe email metadata (subject + snippet only)."""
import html
import json
import re
from datetime import date, datetime, time, timedelta
from pathlib import Path

KEYWORDS = (
    'appointment', 'interview', 'reservation', 'booking', 'consultation', 'telehealth',
    'scheduled for', 'confirmed for', 'your visit', 'meeting invitation', 'invitation:', 'reminder:',
)
STRONG = ('appointment', 'interview', 'reservation', 'consultation', 'telehealth')
MONTHS = {m: i for i, m in enumerate(
    ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'], 1)}

MONTH_RE = re.compile(
    r'\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|'
    r'oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(\d{4}))?\b', re.I)
NUM_RE = re.compile(r'\b(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?\b')
REL_RE = re.compile(r'\b(today|tomorrow)\b', re.I)
TIME_RE = re.compile(r'\b(\d{1,2})(?::(\d{2}))?\s*([ap])\.?m\b\.?', re.I)


def _clean(text):
    text = html.unescape(text or '')
    return re.sub(r'\s+', ' ', re.sub(r'[\u200b-\u200f\u034f\u2060\ufeff\u00ad\u202f\xa0]', ' ', text)).strip()


def _resolve_year(month, day, year, today):
    if year:
        year = int(year)
        return year + 2000 if year < 100 else year
    candidate = date(today.year, month, day)
    return today.year + 1 if candidate < today - timedelta(days=30) else today.year


def _find_date(text, today):
    m = MONTH_RE.search(text)
    try:
        if m:
            month = MONTHS[m.group(1)[:3].lower()]
            day = int(m.group(2))
            return date(_resolve_year(month, day, m.group(3), today), month, day)
        m = NUM_RE.search(text)
        if m:
            month, day = int(m.group(1)), int(m.group(2))
            return date(_resolve_year(month, day, m.group(3), today), month, day)
    except ValueError:
        return None
    m = REL_RE.search(text)
    if m:
        return today + timedelta(days=1 if m.group(1).lower() == 'tomorrow' else 0)
    return None


def _find_time(text):
    m = TIME_RE.search(text)
    if not m:
        return None
    hour, minute = int(m.group(1)), int(m.group(2) or 0)
    if not (1 <= hour <= 12 and minute < 60):
        return None
    hour = hour % 12 + (12 if m.group(3).lower() == 'p' else 0)
    return time(hour, minute)


def detect_appointment(message, today=None):
    today = today or date.today()
    subject = _clean(message.get('subject'))
    snippet = _clean(message.get('snippet'))
    text = f'{subject}. {snippet}'
    low = text.lower()
    if not any(k in low for k in KEYWORDS):
        return None
    when_date = _find_date(text, today)
    if when_date is None:
        if any(k in low for k in STRONG) and any(k in subject.lower() for k in STRONG):
            return {'id': message.get('id'), 'title': subject, 'date': None, 'time': None,
                    'from': message.get('from', ''), 'note': 'date not shown in preview - open the email'}
        return None
    if when_date < today:
        return None
    when_time = _find_time(text)
    return {'id': message.get('id'), 'title': subject or '(no subject)', 'date': when_date.isoformat(),
            'time': when_time.strftime('%H:%M') if when_time else None,
            'from': message.get('from', ''), 'note': ''}


def appointment_key(appt):
    return f"{appt['title'].lower()}|{appt['date']}|{appt['time']}"


def load_store(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []


def merge_store(path, detected, today=None):
    """Merge newly detected dated appointments into the store; drop past ones. Returns (upcoming, new_keys)."""
    today = today or date.today()
    stored = [a for a in load_store(path) if a.get('date') and a['date'] >= today.isoformat()]
    known = {appointment_key(a) for a in stored}
    new_keys = set()
    for appt in detected:
        if not appt.get('date'):
            continue
        key = appointment_key(appt)
        if key not in known:
            known.add(key)
            new_keys.add(key)
            stored.append(appt)
    stored.sort(key=lambda a: (a['date'], a.get('time') or ''))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(stored, indent=2), encoding='utf-8')
    return stored, new_keys


def _ics_escape(text):
    return text.replace('\\', '\\\\').replace(';', '\\;').replace(',', '\\,').replace('\n', ' ')


def build_ics(appointments, now=None):
    now = now or datetime.now()
    stamp = now.strftime('%Y%m%dT%H%M%S')
    lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Stuben//Email Companion//EN']
    for i, appt in enumerate(a for a in appointments if a.get('date')):
        d = appt['date'].replace('-', '')
        lines += ['BEGIN:VEVENT', f'UID:stuben-{i}-{d}-{abs(hash(appointment_key(appt))) % 10**8}@stuben',
                  f'DTSTAMP:{stamp}', f"SUMMARY:{_ics_escape(appt['title'])}"]
        if appt.get('time'):
            t = appt['time'].replace(':', '') + '00'
            start = datetime.strptime(f"{appt['date']} {appt['time']}", '%Y-%m-%d %H:%M')
            end = start + timedelta(hours=1)
            lines += [f'DTSTART:{d}T{t}', f"DTEND:{end.strftime('%Y%m%dT%H%M%S')}"]
            alarms = ('-P1D', '-PT1H')
        else:
            nxt = (datetime.strptime(appt['date'], '%Y-%m-%d') + timedelta(days=1)).strftime('%Y%m%d')
            lines += [f'DTSTART;VALUE=DATE:{d}', f'DTEND;VALUE=DATE:{nxt}']
            alarms = ('-PT15H',)
        for trigger in alarms:
            lines += ['BEGIN:VALARM', 'ACTION:DISPLAY', f"DESCRIPTION:{_ics_escape(appt['title'])}",
                      f'TRIGGER:{trigger}', 'END:VALARM']
        lines.append('END:VEVENT')
    lines.append('END:VCALENDAR')
    return '\r\n'.join(lines) + '\r\n'
