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
        print('HELP\nshow desktop app: python agent.py desktop\nscan > python agent.py scan <path>\nquick review: python agent.py r <file>')
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

    print('Unknown command. Use: python agent.py desktop')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
