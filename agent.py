#!/usr/bin/env python3
import io
import sys

from desktop_app import launch_app

if sys.platform == 'win32' and hasattr(sys.stdout, 'buffer'):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass


def main():
    args = sys.argv[1:]
    if not args or args[0].lower() in {'desktop', 'ui'}:
        launch_app()
        return 0

    command = args[0].lower()
    if command == 'help':
        print('HELP\nshow desktop app: python agent.py desktop\nscan > python agent.py scan <path>\nquick review: python agent.py r <file>\nemail setup (once): python agent.py gmail-auth\nemail digest: python agent.py email-digest [--query Q] [--limit N] [--output FILE]')
        return 0

    if command == 'scan':
        from analyzer import CodeAnalyzer

        path = args[1] if len(args) > 1 else '.'
        findings = CodeAnalyzer().analyze_directory(path, recursive=True)
        print('SCAN')
        print(f'Findings: {len(findings)}')
        for item in findings[:10]:
            print(f"- {item.get('file')}:{item.get('line')} [{item.get('severity')}] {item.get('pattern_name')}")
        return 0

    if command == 'r':
        from analyzer import CodeAnalyzer
        from report_generator import ReportGenerator

        target = args[1] if len(args) > 1 else '.'
        findings = CodeAnalyzer().analyze_file(target)
        print(ReportGenerator().generate(findings, 'text'))
        return 0

    if command == 'gmail-auth':
        from gmail_integration import GmailIntegration

        GmailIntegration().authenticate(interactive=True)
        print('Gmail authorized (read-only). Token saved to gmail_token.json')
        return 0

    if command == 'email-digest':
        from email_digest import write_digest
        from gmail_integration import GmailIntegration

        query = 'in:inbox newer_than:1d'
        output = None
        limit = 100
        rest = args[1:]
        for i, a in enumerate(rest):
            if a == '--query' and i + 1 < len(rest):
                query = rest[i + 1]
            elif a == '--output' and i + 1 < len(rest):
                output = rest[i + 1]
            elif a == '--limit' and i + 1 < len(rest):
                limit = int(rest[i + 1])
        try:
            result = GmailIntegration().scan_messages(query=query, limit=limit)
        except RuntimeError as exc:
            print(f'ERROR: {exc}')
            return 2
        path, digest = write_digest(result['messages'], output)
        c = digest['counts']
        print(f"Digest written: {path} ({c['safe']} safe, {c['suspicious']} suspicious, {c['junk']} junk)")
        return 0

    print('Unknown command. Use: python agent.py desktop')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
