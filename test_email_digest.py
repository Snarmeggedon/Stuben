import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

from appointments import build_ics, detect_appointment, merge_store
from email_digest import build_digest, render_markdown, write_digest
from email_vetting import JUNK, SAFE, SUSPICIOUS, vet_message


def msg(sender, subject, snippet='', headers=None, attachments=None, labels=None, mid='1'):
    h = {'authentication-results': ['mx.google.com; spf=pass; dkim=pass; dmarc=pass']}
    h.update(headers or {})
    return {'id': mid, 'from': sender, 'subject': subject, 'snippet': snippet, 'headers': h,
            'attachments': attachments or [], 'labels': labels or []}


class VettingTests(unittest.TestCase):
    def test_normal_mail_is_safe(self):
        self.assertEqual(vet_message(msg('Ann <ann@example.com>', 'Lunch?', 'Free Friday?'))['verdict'], SAFE)

    def test_failed_auth_and_brand_spoof_suspicious(self):
        m = msg('PayPal Support <help@secure-pay.xyz>', 'Verify your account',
                headers={'authentication-results': ['spf=fail; dkim=fail; dmarc=fail']})
        r = vet_message(m)
        self.assertEqual(r['verdict'], SUSPICIOUS)
        self.assertFalse(r['may_open_body'])

    def test_reply_to_mismatch(self):
        m = msg('hr@acme.com', 'Doc', headers={'reply-to': ['x@evil.ru']})
        self.assertTrue(any('reply-to' in r for r in vet_message(m)['reasons']))

    def test_risky_attachment(self):
        m = msg('a@b.com', 'Invoice', attachments=[{'filename': 'invoice.pdf.exe', 'mime_type': ''}])
        self.assertEqual(vet_message(m)['verdict'], SUSPICIOUS)

    def test_ip_link(self):
        m = msg('a@b.com', 'Hi', 'see http://192.168.4.4/login to verify your account',
                headers={'authentication-results': ['spf=softfail']})
        self.assertEqual(vet_message(m)['verdict'], SUSPICIOUS)

    def test_marketing_is_junk(self):
        m = msg('deals@shop.com', 'Flash sale 50% off', 'Buy now, free shipping. Unsubscribe',
                headers={'list-unsubscribe': ['<mailto:u@shop.com>']}, labels=['CATEGORY_PROMOTIONS'])
        self.assertEqual(vet_message(m)['verdict'], JUNK)


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.msgs = [
            msg('jobs@greenhouse.io', 'Interview invitation', 'Schedule your interview', mid='1'),
            msg('bank@example.com', 'Payment due tomorrow', 'Your bill is due', mid='2'),
            msg('friend@example.com', 'Photos', 'From the trip', mid='3'),
            msg('PayPal <x@evil.xyz>', 'Verify your account', 'urgent', mid='4',
                headers={'authentication-results': ['spf=fail']}),
            msg('deals@shop.com', 'Sale', 'Flash sale buy now unsubscribe', mid='5', labels=['CATEGORY_PROMOTIONS']),
        ]

    def test_grouping_and_filtering(self):
        d = build_digest(self.msgs)
        self.assertEqual([m['id'] for m in d['groups']['job']], ['1'])
        self.assertEqual([m['id'] for m in d['groups']['important']], ['2'])
        self.assertEqual([m['id'] for m in d['groups']['fyi']], ['3'])
        self.assertEqual(d['counts'], {SAFE: 3, SUSPICIOUS: 1, JUNK: 1})

    def test_markdown_excludes_filtered_content(self):
        text = render_markdown(build_digest(self.msgs, datetime(2026, 1, 1, 8)))
        self.assertIn('Job Application Updates', text)
        self.assertNotIn('Verify your account', text)
        self.assertNotIn('Flash sale', text)

    def test_write_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = write_digest(self.msgs, Path(tmp) / 'd.md', quarantine_dir=Path(tmp) / 'q')
            self.assertTrue(path.exists())
            self.assertEqual(len(list((Path(tmp) / 'q').glob('*.json'))), 1)


class AppointmentTests(unittest.TestCase):
    TODAY = date(2026, 11, 10)

    def test_dated_appointment_with_time(self):
        m = msg('clinic@example.com', 'Your appointment is confirmed', 'See you Nov 12 at 3:30 PM at Geisinger')
        a = detect_appointment(m, self.TODAY)
        self.assertEqual((a['date'], a['time']), ('2026-11-12', '15:30'))

    def test_past_and_undated_are_ignored(self):
        self.assertIsNone(detect_appointment(msg('a@b.com', 'Appointment recap', 'was on Nov 1'), self.TODAY))
        self.assertIsNone(detect_appointment(msg('a@b.com', 'Newsletter', 'weekly deals'), self.TODAY))

    def test_interview_without_date_flagged(self):
        a = detect_appointment(msg('hr@acme.com', 'Interview invitation', 'Please pick a slot'), self.TODAY)
        self.assertIsNone(a['date'])

    def test_store_dedupes_and_ics(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = detect_appointment(msg('c@x.com', 'Dentist appointment', 'tomorrow at 9am'), self.TODAY)
            store = Path(tmp) / 's.json'
            _, new1 = merge_store(store, [a], self.TODAY)
            upcoming, new2 = merge_store(store, [a], self.TODAY)
            self.assertEqual((len(new1), len(new2), len(upcoming)), (1, 0, 1))
            self.assertIn('TRIGGER:-PT1H', build_ics(upcoming))

    def test_digest_section_and_ics_written(self):
        msgs = [msg('clinic@example.com', 'Appointment reminder', 'Dr. visit on Dec 30 at 10:00 AM', mid='9')]
        with tempfile.TemporaryDirectory() as tmp:
            path, digest = write_digest(msgs, Path(tmp) / 'd.md', quarantine_dir=Path(tmp) / 'q',
                                        now=datetime(2026, 11, 10, 8))
            self.assertIn('Appointments & Reminders (1)', path.read_text(encoding='utf-8'))
            self.assertTrue(path.with_suffix('.ics').exists())


if __name__ == '__main__':
    unittest.main()
