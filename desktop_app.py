import threading
import tkinter as tk
from tkinter import PhotoImage
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, scrolledtext
import time

from analyzer import CodeAnalyzer
from gmail_integration import GmailIntegration
from report_generator import ReportGenerator
from sec_advisor import SecurityAdvisor
from threat_analyst import ThreatAnalyst
from action_history import ActionHistory
from threat_scorer import EnhancedThreatScorer
from system_monitor import SystemMonitor


class SecurityDashboard:
    GOOGLE_OAUTH_URL = 'https://console.cloud.google.com/apis/credentials'
    GMAIL_QUICKSTART_URL = 'https://developers.google.com/gmail/api/quickstart/python'

    def __init__(self):
        self.root = tk.Tk()
        self.root.title('Stuben')
        self.root.geometry('1280x820')
        self.root.configure(bg='#0b1220')

        self.analyzer = CodeAnalyzer()
        self.report_generator = ReportGenerator()
        self.threat_analyst = ThreatAnalyst()
        self.advisor = SecurityAdvisor()
        self.history = ActionHistory()
        self.threat_scorer = EnhancedThreatScorer()
        self.system_monitor = SystemMonitor()

        self.quarantine_dir = Path(__file__).resolve().parent / 'quarantine'
        self.quarantine_dir.mkdir(exist_ok=True)

        self.gmail_credentials_path = None
        self.last_review_path = None
        self.avatar_var = tk.StringVar(value='Stuben is online and ready to assist.')
        self.status_var = tk.StringVar(value='Ready')
        
        self.right_panel = None
        self.tips_label = None
        self.recommendations_frame = None
        self._last_findings = []
        self._scan_start_time = None
        self.system_status_label = None  # For system monitoring display
        
        # Animation state
        self.animation_frame = 0
        self.animation_state = 'idle'  # idle, scanning, talking, alert, success
        
        # Progress tracking
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_label_var = tk.StringVar(value="")
        self.icon_path = self._ensure_stuben_icon()
        self._stuben_icon_image = None

        self._build_layout()
        self._style_output()
        self._animate_avatar()
        self.write_output('SYSTEM', 'Stuben ready. Select a quick action or type help.')
        
        self.root.bind('<Configure>', self._on_window_resize)

    def _build_layout(self):
        if self.icon_path and Path(self.icon_path).exists():
            try:
                self._stuben_icon_image = PhotoImage(file=str(self.icon_path))
                self.root.iconphoto(True, self._stuben_icon_image)
            except Exception:
                try:
                    self.root.iconbitmap(default=str(self.icon_path))
                except Exception:
                    pass

        header = tk.Frame(self.root, bg='#111827', height=60)
        header.pack(fill='x')
        header.pack_propagate(False)

        tk.Label(
            header,
            text='Stuben - Cybersecurity Assistant',
            bg='#111827',
            fg='#f9fafb',
            font=('Segoe UI', 20, 'bold'),
        ).pack(side='left', padx=18, pady=12)
        tk.Label(
            header,
            textvariable=self.status_var,
            bg='#111827',
            fg='#93c5fd',
            font=('Segoe UI', 11, 'bold'),
        ).pack(side='right', padx=18)

        # Progress bar and percentage
        progress_container = tk.Frame(header, bg='#111827')
        progress_container.pack(side='right', padx=18, pady=8)
        
        try:
            # Try to use ttk for modern progress bar
            import tkinter.ttk as ttk
            self.progress_bar = ttk.Progressbar(
                progress_container,
                length=200,
                mode='determinate',
                variable=self.progress_var,
                style='TProgressbar'
            )
            self.progress_bar.pack(side='left', padx=(0, 8))
        except Exception:
            # Fallback: custom progress bar using canvas
            self.progress_canvas = tk.Canvas(progress_container, width=200, height=8, bg='#1f2937', highlightthickness=0)
            self.progress_canvas.pack(side='left', padx=(0, 8))
            self.progress_fill = None
        
        tk.Label(
            progress_container,
            textvariable=self.progress_label_var,
            bg='#111827',
            fg='#60a5fa',
            font=('Segoe UI', 9, 'bold'),
            width=6,
        ).pack(side='left')

        body = tk.Frame(self.root, bg='#0b1220')
        body.pack(fill='both', expand=True, padx=14, pady=14)

        left = tk.Frame(body, bg='#111827', width=260)
        left.pack(side='left', fill='y', padx=(0, 12))
        left.pack_propagate(False)

        center = tk.Frame(body, bg='#111827')
        center.pack(side='left', fill='both', expand=True, padx=(0, 12))

        self.right_panel = tk.Frame(body, bg='#111827')
        self.right_panel.pack(side='left', fill='both', expand=True, padx=0)

        self._build_quick_actions(left)
        self._build_console(center)
        self._build_avatar_panel(self.right_panel)

    def _build_quick_actions(self, parent):
        tk.Label(parent, text='Quick Actions', bg='#111827', fg='#f9fafb', font=('Segoe UI', 13, 'bold')).pack(anchor='w', padx=16, pady=(16, 8))

        actions = [
            ('Scan Downloads', lambda: self.queue_scan(str(Path.home() / 'Downloads'), True, 'Scanning downloads')),
            ('Scan Documents', lambda: self.queue_scan(str(Path.home() / 'Documents'), True, 'Scanning documents')),
            ('Scan Stuben Dir', lambda: self.queue_scan(str(Path(__file__).parent), True, 'Scanning Stuben directory')),
            ('AI Threat Scan', self.scan_ai_threats),
            ('Review File...', self.pick_review_file),
            ('Threat Check...', self.pick_threat_file),
            ('Quarantine File...', self.pick_quarantine_file),
            ('Select Gmail Credentials...', self.pick_gmail_credentials),
            ('Open Google OAuth Setup', self.open_google_oauth_setup),
            ('Gmail Connect', self.queue_gmail_auth),
            ('Show Help', self.show_help),
        ]

        for label, handler in actions:
            tk.Button(
                parent,
                text=label,
                command=handler,
                bg='#1d4ed8',
                fg='#ffffff',
                activebackground='#1d4ed8',
                relief='flat',
                font=('Segoe UI', 10, 'bold'),
                padx=10,
                pady=9,
            ).pack(fill='x', padx=16, pady=5)

    def _build_console(self, parent):
        tk.Label(parent, text='Operations', bg='#111827', fg='#f9fafb', font=('Segoe UI', 13, 'bold')).pack(anchor='w', padx=16, pady=(16, 8))

        command_bar = tk.Frame(parent, bg='#111827')
        command_bar.pack(fill='x', padx=16, pady=(0, 10))

        self.command_entry = tk.Entry(
            command_bar,
            bg='#0b1220',
            fg='#f9fafb',
            insertbackground='#f9fafb',
            relief='flat',
            font=('Consolas', 12),
        )
        self.command_entry.pack(side='left', fill='x', expand=True, ipady=10, padx=(0, 10))
        self.command_entry.bind('<Return>', lambda _: self.run_command())

        tk.Button(
            command_bar,
            text='Run',
            command=self.run_command,
            bg='#2563eb',
            fg='#ffffff',
            relief='flat',
            font=('Segoe UI', 10, 'bold'),
            padx=18,
            pady=10,
        ).pack(side='left')

        self.output = scrolledtext.ScrolledText(
            parent,
            wrap='word',
            bg='#020617',
            fg='#e5e7eb',
            relief='flat',
            font=('Consolas', 11),
            padx=12,
            pady=12,
        )
        self.output.pack(fill='both', expand=True, padx=16, pady=(0, 16))

    def _build_avatar_panel(self, parent):
        tk.Label(parent, text='Stuben - sentinel guide', bg='#111827', fg='#f9fafb', font=('Segoe UI', 13, 'bold')).pack(anchor='w', padx=18, pady=(18, 8))
        self.avatar_canvas = tk.Canvas(parent, width=200, height=180, bg='#111827', highlightthickness=0)
        self.avatar_canvas.pack(padx=20, pady=8)
        self._draw_avatar()

        avatar_text_frame = tk.Frame(parent, bg='#1f2937')
        avatar_text_frame.pack(fill='x', padx=18, pady=(8, 18))
        
        tk.Label(
            avatar_text_frame,
            textvariable=self.avatar_var,
            justify='left',
            bg='#1f2937',
            fg='#e5e7eb',
            font=('Segoe UI', 9),
            padx=14,
            pady=12,
            wraplength=300,
        ).pack(fill='both', expand=True)

        tk.Label(parent, text='Tips', bg='#111827', fg='#f9fafb', font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=18, pady=(12, 6))
        
        self.tips_label = tk.Label(
            parent,
            text='- Scan Downloads\n- AI Threat Scan\n- Review File\n- Export to HTML\n- Quarantine unsafe files',
            justify='left',
            bg='#111827',
            fg='#cbd5e1',
            font=('Segoe UI', 9),
            wraplength=300,
            padx=18,
            pady=8,
        )
        self.tips_label.pack(fill='x', anchor='w')

        tk.Label(parent, text='Recommended Actions', bg='#111827', fg='#f9fafb', font=('Segoe UI', 11, 'bold')).pack(anchor='w', padx=18, pady=(12, 6))
        
        # Create a scrollable frame using Canvas
        self._create_scrollable_recommendations_frame(parent)
        
        self.update_recommendations([])
    
    def _create_scrollable_recommendations_frame(self, parent):
        """Create a scrollable frame for recommendations with proper mouse wheel support."""
        # Container frame
        container = tk.Frame(parent, bg='#111827')
        container.pack(fill='both', expand=True, padx=18, pady=(0, 12))
        
        # Canvas
        self.rec_canvas = tk.Canvas(
            container,
            bg='#111827',
            highlightthickness=0,
            relief='flat',
            height=250
        )
        self.rec_canvas.pack(side='left', fill='both', expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(container, command=self.rec_canvas.yview, bg='#1f2937')
        scrollbar.pack(side='right', fill='y')
        self.rec_canvas.config(yscrollcommand=scrollbar.set)
        
        # Inner frame for content
        self.recommendation_frame = tk.Frame(self.rec_canvas, bg='#111827')
        self.rec_canvas_window = self.rec_canvas.create_window(0, 0, window=self.recommendation_frame, anchor='nw')
        
        # Bind scroll region updates
        self.recommendation_frame.bind('<Configure>', self._on_rec_frame_config)
        self.rec_canvas.bind('<Configure>', self._on_rec_canvas_config)
        
        # Enable mousewheel scrolling
        self.rec_canvas.bind('<MouseWheel>', self._rec_mousewheel)
        self.rec_canvas.bind('<Button-4>', lambda e: self.rec_canvas.yview_scroll(-3, 'units'))
        self.rec_canvas.bind('<Button-5>', lambda e: self.rec_canvas.yview_scroll(3, 'units'))
    
    def _on_rec_frame_config(self, event=None):
        """Update scroll region when recommendation frame changes."""
        self.rec_canvas.configure(scrollregion=self.rec_canvas.bbox('all'))
    
    def _on_rec_canvas_config(self, event=None):
        """Update scroll region and window width when canvas changes."""
        self.rec_canvas.configure(scrollregion=self.rec_canvas.bbox('all'))
        canvas_width = self.rec_canvas.winfo_width()
        if canvas_width > 1:
            self.rec_canvas.itemconfig(self.rec_canvas_window, width=canvas_width)
    
    def _rec_mousewheel(self, event):
        """Handle mousewheel on recommendations canvas."""
        self.rec_canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
        return 'break'

    def _on_window_resize(self, event):
        if self.right_panel and self.tips_label:
            width = self.right_panel.winfo_width()
            if width > 1:
                wraplength = max(int(width * 0.85), 200)
                self.tips_label.configure(wraplength=wraplength)
                if hasattr(self, 'recommendation_frame') and self.recommendation_frame:
                    for widget in self.recommendation_frame.winfo_children():
                        if isinstance(widget, tk.Button):
                            widget.configure(wraplength=max(wraplength - 30, 170))



    def _style_output(self):
        self.output.tag_configure('title', foreground='#93c5fd', font=('Consolas', 12, 'bold'))
        self.output.tag_configure('ok', foreground='#4ade80')
        self.output.tag_configure('warn', foreground='#fbbf24')
        self.output.tag_configure('critical', foreground='#f87171')
        self.output.tag_configure('accent', foreground='#c084fc')
        self.output.tag_configure('info', foreground='#cbd5e1')

    def _draw_avatar(self):
        canvas = self.avatar_canvas
        canvas.delete('all')
        
        # Base head - centered at x=50-130 (canvas width 200)
        canvas.create_oval(50, 46, 130, 126, fill='#d6d3d1', outline='#9ca3af', width=3)
        canvas.create_oval(62, 60, 118, 112, fill='#e7e5e4')
        
        # Animation effects
        if self.animation_state == 'idle':
            # Breathing glow effect
            glow_alpha = 0.3 + 0.2 * abs(((self.animation_frame % 60) - 30) / 30)
            glow_color = f'#{int(93 + glow_alpha * 60):02x}{int(197 + glow_alpha * 30):02x}{int(253 + glow_alpha * 0):02x}'
            canvas.create_oval(45, 40, 135, 135, outline=glow_color, width=2)
            
            # Normal eyes
            canvas.create_oval(66, 74, 86, 98, fill='#7f1d1d')
            canvas.create_oval(94, 74, 114, 98, fill='#7f1d1d')
            canvas.create_oval(74, 82, 82, 90, fill='#fca5a5')
            canvas.create_oval(98, 82, 106, 90, fill='#fca5a5')
        
        elif self.animation_state == 'scanning':
            # Scanning animation - rotating scanner beams
            rotation = (self.animation_frame % 60) * 6
            import math
            cx, cy = 90, 90
            radius = 35
            x1 = cx + radius * math.cos(math.radians(rotation))
            y1 = cy + radius * math.sin(math.radians(rotation))
            canvas.create_line(cx, cy, x1, y1, fill='#60a5fa', width=3)
            
            # Pulsing eyes
            pulse = 0.5 + 0.5 * abs(((self.animation_frame % 30) - 15) / 15)
            eye_fill = f'#{int(127 + pulse * 80):02x}{int(29 + pulse * 100):02x}{int(29 + pulse * 100):02x}'
            canvas.create_oval(66, 74, 86, 98, fill=eye_fill)
            canvas.create_oval(94, 74, 114, 98, fill=eye_fill)
            canvas.create_oval(74, 82, 82, 90, fill='#fca5a5')
            canvas.create_oval(98, 82, 106, 90, fill='#fca5a5')
            
            # Scanning text indicator
            canvas.create_text(90, 20, text='SCANNING', fill='#60a5fa', font=('Segoe UI', 10, 'bold'))
        
        elif self.animation_state == 'talking':
            # Bouncing animation
            bounce = 3 * abs(((self.animation_frame % 20) - 10) / 10)
            
            # Bouncing eyes
            canvas.create_oval(66, 74 - bounce, 86, 98 - bounce, fill='#7f1d1d')
            canvas.create_oval(94, 74 - bounce, 114, 98 - bounce, fill='#7f1d1d')
            canvas.create_oval(74, 82 - bounce, 82, 90 - bounce, fill='#fca5a5')
            canvas.create_oval(98, 82 - bounce, 106, 90 - bounce, fill='#fca5a5')
            
            # Animated mouth (opening/closing)
            mouth_open = 0.3 + 0.7 * abs(((self.animation_frame % 15) - 7.5) / 7.5)
            mouth_height = int(10 * mouth_open)
            canvas.create_arc(62, 104, 118, 104 + mouth_height, start=180, extent=180, style='arc', outline='#52525b', width=4)
            
            # Talking indicator
            canvas.create_text(90, 20, text='ANALYZING', fill='#c084fc', font=('Segoe UI', 10, 'bold'))
        
        elif self.animation_state == 'alert':
            # Red pulsing alert
            pulse = 0.4 + 0.6 * abs(((self.animation_frame % 15) - 7.5) / 7.5)
            alert_color = f'#{int(248 + pulse * 7):02x}{int(113 - pulse * 50):02x}{int(113 - pulse * 50):02x}'
            
            canvas.create_oval(45, 40, 135, 135, outline=alert_color, width=4)
            
            # Alert eyes
            canvas.create_oval(66, 74, 86, 98, fill='#dc2626')
            canvas.create_oval(94, 74, 114, 98, fill='#dc2626')
            canvas.create_oval(74, 82, 82, 90, fill='#fca5a5')
            canvas.create_oval(98, 82, 106, 90, fill='#fca5a5')
            
            # Shaking effect
            shake = 2 * ((self.animation_frame % 8) - 4) / 4
            canvas.create_arc(62 + shake, 104, 118 + shake, 146, start=0, extent=180, style='arc', outline='#dc2626', width=4)
            
            # Alert indicator
            canvas.create_text(90, 20, text='THREAT DETECTED', fill='#dc2626', font=('Segoe UI', 9, 'bold'))
        
        elif self.animation_state == 'success':
            # Green success glow
            glow_intensity = 0.5 + 0.5 * abs(((self.animation_frame % 30) - 15) / 15)
            glow_color = f'#{int(74 + glow_intensity * 60):02x}{int(222 + glow_intensity * 33):02x}{int(128 + glow_intensity * 0):02x}'
            canvas.create_oval(45, 40, 135, 135, outline=glow_color, width=3)
            
            # Happy eyes
            canvas.create_oval(66, 74, 86, 98, fill='#7f1d1d')
            canvas.create_oval(94, 74, 114, 98, fill='#7f1d1d')
            canvas.create_oval(74, 82, 82, 90, fill='#fca5a5')
            canvas.create_oval(98, 82, 106, 90, fill='#fca5a5')
            
            # Smiling mouth
            canvas.create_arc(62, 104, 118, 146, start=180, extent=180, style='arc', outline='#22c55e', width=4)
            
            # Success indicator
            canvas.create_text(90, 20, text='SAFE', fill='#22c55e', font=('Segoe UI', 10, 'bold'))
        
        else:
            # Default idle
            canvas.create_oval(66, 74, 86, 98, fill='#7f1d1d')
            canvas.create_oval(94, 74, 114, 98, fill='#7f1d1d')
            canvas.create_oval(74, 82, 82, 90, fill='#fca5a5')
            canvas.create_oval(98, 82, 106, 90, fill='#fca5a5')
        
        canvas.create_rectangle(68, 116, 112, 126, fill='#0f172a', outline='#52525b', width=2)
        canvas.create_text(90, 160, text='Stuben', fill='#cbd5e1', font=('Segoe UI', 12, 'bold'))

    def _ensure_stuben_icon(self):
        """Use the generated Stuben face icon."""
        icon_dir = Path(__file__).resolve().parent / 'assets'
        icon_dir.mkdir(exist_ok=True)
        icon_path = icon_dir / 'stuben_face.png'
        return icon_path

    def _animate_avatar(self):
        self.animation_frame = (self.animation_frame + 1) % 120
        self._draw_avatar()
        self.root.after(50, self._animate_avatar)
    
    def set_animation_state(self, state):
        """Change avatar animation state: idle, scanning, talking, alert, success"""
        self.animation_state = state
        self.animation_frame = 0
    
    def update_progress(self, current, total):
        """Update scan progress bar. Call from worker thread using root.after()"""
        if total <= 0:
            percentage = 0
        else:
            percentage = min(100, (current / total) * 100)
        
        self.progress_var.set(percentage)
        self.progress_label_var.set(f"{int(percentage)}%")
        
        # Update custom canvas progress bar if ttk is not available
        if hasattr(self, 'progress_canvas'):
            self.progress_canvas.delete(self.progress_fill)
            width = (percentage / 100) * 200
            self.progress_fill = self.progress_canvas.create_rectangle(0, 0, width, 8, fill='#60a5fa', outline='#60a5fa')
    
    def reset_progress(self):
        """Reset progress bar"""
        self.progress_var.set(0.0)
        self.progress_label_var.set("")

    def set_status(self, value):
        self.status_var.set(value)

    def update_recommendations(self, findings):
        """Display per-threat action buttons and Stuben's questions with scrolling support."""
        # Clear previous recommendations
        for widget in self.recommendation_frame.winfo_children():
            widget.destroy()
        
        if not findings:
            return

        # Show threat score header
        threat_score = self.threat_scorer.calculate_cvss_score(findings)
        risk_level, emoji = self.threat_scorer.get_risk_level(threat_score)
        attack_profile = self.threat_scorer.get_attack_profile(findings)
        
        # Header frame
        header_frame = tk.Frame(self.recommendation_frame, bg='#111827')
        header_frame.pack(fill='x', padx=8, pady=(8, 4))
        
        tk.Label(
            header_frame,
            text=f"{emoji} THREAT SCORE: {threat_score:.1f}/10 ({risk_level})",
            bg='#111827',
            fg='#fbbf24',
            font=('Segoe UI', 10, 'bold')
        ).pack(anchor='w')
        
        tk.Label(
            header_frame,
            text=f"Attack Profile: {attack_profile}",
            bg='#111827',
            fg='#e5e7eb',
            font=('Segoe UI', 9)
        ).pack(anchor='w')

        # Show per-threat actions and questions for top 5 findings
        for idx, finding in enumerate(findings[:5]):
            pattern = finding.get("pattern_name", "unknown")
            severity = finding.get("severity", "low").upper()
            
            # Get Stuben's question about this threat
            question = self.advisor.get_threat_question(pattern)
            threat_info = self.advisor.get_threat_actions(pattern)
            actions = threat_info.get("actions", [])
            
            # Threat container
            threat_frame = tk.Frame(self.recommendation_frame, bg='#1f2937', relief='flat')
            threat_frame.pack(fill='x', padx=8, pady=(8, 4))
            
            # Threat header
            header = tk.Label(
                threat_frame,
                text=f"{pattern.upper()} [{severity}]",
                bg='#1f2937',
                fg='#fbbf24',
                font=('Segoe UI', 9, 'bold')
            )
            header.pack(anchor='w', padx=8, pady=(8, 4))
            
            # Stuben's question
            question_label = tk.Label(
                threat_frame,
                text=f"❓ {question}",
                bg='#1f2937',
                fg='#c084fc',
                font=('Segoe UI', 8, 'italic'),
                wraplength=280,
                justify='left'
            )
            question_label.pack(anchor='w', padx=8, pady=(0, 6))
            
            # Action buttons
            for action in actions[:3]:
                action_btn = tk.Button(
                    threat_frame,
                    text=f"→ {action}",
                    bg='#374151',
                    fg='#60a5fa',
                    font=('Segoe UI', 8),
                    relief='flat',
                    padx=8,
                    pady=4,
                    cursor='hand2',
                    activebackground='#4b5563',
                    activeforeground='#93c5fd',
                    command=lambda a=action, p=pattern: self._execute_action(a, p)
                )
                action_btn.pack(anchor='w', padx=12, pady=2, fill='x')
            
            # Divider
            if idx < min(4, len(findings) - 1):
                divider = tk.Frame(self.recommendation_frame, bg='#374151', height=1)
                divider.pack(fill='x', padx=8, pady=8)
    
    def _execute_action(self, action, pattern):
        """Execute a recommended action."""
        print(f"[ACTION] Executing: {action} for pattern: {pattern}")
        
        # Log the action
        self.action_history.log_action(action, pattern)
        
        # Map actions to actual functions
        action_lower = action.lower()
        
        if "quarantine" in action_lower or "isolate" in action_lower:
            self.queue_scan("isolate_threat")
        elif "remove" in action_lower or "delete" in action_lower:
            self.queue_scan("remove_threat")
        elif "sandbox" in action_lower or "analyze" in action_lower:
            self.queue_scan("analyze_threat")
        elif "scan" in action_lower:
            self.queue_scan("deep_scan")
        elif "update" in action_lower or "patch" in action_lower:
            print("[INFO] Update action recommended - consult system updates")
        elif "review" in action_lower or "manual" in action_lower:
            print("[INFO] Manual review recommended")
        else:
            print(f"[INFO] Action: {action}")

    def execute_threat_action(self, action, pattern):
        """Execute a recommended action for a specific threat."""
        text = action.lower()
        severity = "unknown"
        
        # Find severity of this threat for context
        if hasattr(self, '_last_findings'):
            for finding in self._last_findings:
                if finding.get("pattern_name", "").lower() == pattern.lower():
                    severity = finding.get("severity", "medium")
                    break
        
        # Log action to history
        self.history.log_action(
            action_type="action_taken",
            threat_pattern=pattern,
            action_name=action,
            details=f"Severity: {severity}",
            success=True
        )
        
        # Display the action being taken
        self.write_output('ACTION', f'[{pattern.upper()}] Executing: {action}')
        
        # Execute threat-specific actions
        if 'quarantine' in text or 'isolate' in text:
            if self.last_review_path and Path(self.last_review_path).exists():
                source = Path(self.last_review_path)
                target = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{source.name}"
                target.write_bytes(source.read_bytes())
                source.unlink()
                self.write_output('SUCCESS', f'✓ Quarantined: {source.name}\n  Stored at: {target}')
                return
            self.pick_quarantine_file()
            return
        
        if 'block' in text or 'firewall' in text or 'network isolation' in text:
            self.write_output('FIREWALL', f'⚠ Firewall follow-up recommended: Block traffic related to this threat and review network logs.')
            return
        
        if 'review' in text or 'manual investigation' in text:
            self.write_output('INVESTIGATION', f'📋 Manual investigation needed: Review the code, logs, and system state for this pattern.')
            return
        
        if 'change password' in text or 'rotation' in text or 'reset' in text:
            self.write_output('CREDENTIALS', f'🔐 Credential action: Consider changing passwords and rotating API keys.')
            return
        
        if 'isolation' in text or 'isolate' in text or 'disconnect' in text:
            self.write_output('ISOLATION', f'🔌 System isolation recommended: Consider disconnecting this system from the network.')
            return
        
        if 'delete' in text or 'remove' in text:
            self.write_output('CLEANUP', f'🗑 Cleanup action: Remove the identified threat artifact (requires manual confirmation).')
            return
        
        # Generic action tracking
        self.write_output('ACTION', f'✓ Action logged: {action}')
    
    def execute_recommendation(self, recommendation):
        text = recommendation.lower()
        if 'quarantine' in text or 'isolate' in text:
            if self.last_review_path and Path(self.last_review_path).exists():
                source = Path(self.last_review_path)
                target = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{source.name}"
                target.write_bytes(source.read_bytes())
                source.unlink()
                self.write_output('ACTION', f'[OK] Quarantined: {source.name}\nStored at: {target}')
                return
            self.pick_quarantine_file()
            return

        if 'block outbound' in text or 'firewall' in text or 'beaconing' in text:
            self.write_output('ACTION', 'Firewall follow-up: block the suspicious outbound connection and review DNS/firewall logs for beaconing.')
            return

        if 'execution logs' in text or 'scheduled tasks' in text or 'powerShell' in text:
            self.write_output('ACTION', 'Host follow-up: review PowerShell execution logs and scheduled tasks for recent suspicious activity.')
            return

        self.write_output('ACTION', f'Next step: {recommendation}')

    def write_output(self, title, text):
        self.output.insert('end', f'{title}\n', 'title')
        for line in str(text).splitlines():
            tag = 'info'
            if '[OK]' in line:
                tag = 'ok'
            elif 'ERROR' in line.upper() or 'CRITICAL' in line.upper():
                tag = 'critical'
            elif 'WARNING' in line.upper() or 'RISK' in line.upper():
                tag = 'warn'
            elif 'GMAIL' in line.upper() or 'THREAT' in line.upper():
                tag = 'accent'
            self.output.insert('end', line + '\n', tag)
        self.output.insert('end', '\n')
        self.output.see('end')

    def queue_scan(self, target, recursive, message):
        def action():
            path = Path(target)
            if not path.exists():
                raise RuntimeError(f'Path not found: {target}')
            self.last_review_path = str(path)
            findings = self.analyzer.analyze_directory(str(path), recursive=recursive)
            return {"message": self.report_generator.generate(findings, 'text'), "findings": findings}

        self.queue_task('SCAN', message, action)

    def queue_task(self, label, message, fn):
        self.set_status(label)
        self.set_animation_state('scanning')
        self.write_output('RUNNING', message)
        self._scan_start_time = time.time()
        
        # Start system monitoring
        self.system_monitor.start_monitoring()

        def worker():
            try:
                result = fn()
                self.root.after(0, lambda r=result, l=label: self._finish_task(l, r))
            except Exception as exc:
                self.root.after(0, lambda e=exc: self._fail_task(str(e)))
            finally:
                # Stop monitoring when done
                self.system_monitor.stop_monitoring()

        threading.Thread(target=worker, daemon=True).start()

    def _format_findings_with_explanations(self, findings):
        """Format findings to include threat explanations, actions, questions, and CVSS-like scoring."""
        if not findings:
            return ""
        
        # Calculate overall threat score
        threat_score = self.threat_scorer.calculate_cvss_score(findings)
        scoring_explanation = self.threat_scorer.generate_scoring_explanation(findings)
        
        lines = [f"\n{'='*80}\nDETAILED THREAT ANALYSIS ({len(findings)} findings)\n{'='*80}\n"]
        lines.append(scoring_explanation)
        lines.append(f"\n{'-'*80}\n")
        
        for idx, item in enumerate(findings[:15], start=1):
            pattern = item.get("pattern_name", "suspicious")
            severity = item.get("severity", "low").upper()
            location = f"{item.get('file', 'unknown')}:{item.get('line', '?')}"
            match = item.get("malicious_line", "")
            explanation = self.report_generator.get_threat_explanation(pattern)
            
            # Get per-threat actions and questions
            threat_info = self.advisor.get_threat_actions(pattern)
            actions = threat_info.get("actions", [])
            question = threat_info.get("question", "Is this expected?")
            
            lines.append(f"\n[FINDING {idx}] {pattern.upper()}")
            lines.append(f"  Severity:   {severity}")
            lines.append(f"  Location:   {location}")
            lines.append(f"  Detected:   {match[:100]}")
            lines.append(f"  Why it matters: {explanation}")
            lines.append(f"  Question:   {question}")
            if actions:
                lines.append(f"  Recommended Actions:")
                for action in actions[:4]:
                    lines.append(f"    • {action}")
        
        if len(findings) > 15:
            lines.append(f"\n... and {len(findings) - 15} more findings (export to HTML for full details)")
        
        return "\n".join(lines)

    def _finish_task(self, label, result):
        self.set_status('Ready')
        self.reset_progress()
        
        # Calculate scan duration and add system monitoring data
        scan_duration = time.time() - self._scan_start_time if self._scan_start_time else 0
        
        if isinstance(result, dict):
            display = result['message']
            findings = result.get('findings', [])
            self._last_findings = findings  # Store for action tracking
            self.update_recommendations(findings)
            
            # Add system monitoring summary
            monitoring_summary = self.system_monitor.format_summary()
            display += f"\n\n{monitoring_summary}"
            
            # Log scan to history
            if label == 'SCAN' or 'AI Threat' in label:
                self.history.log_scan(
                    scan_type=label,
                    file_count=len(findings) if findings else 0,
                    findings_count=len(findings),
                    duration_seconds=scan_duration
                )
            
            # Set animation based on results
            if findings:
                critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
                if critical_count > 0:
                    self.set_animation_state('alert')
                    self.root.after(3000, lambda: self.set_animation_state('idle'))
                else:
                    self.set_animation_state('success')
                    self.root.after(2000, lambda: self.set_animation_state('idle'))
            else:
                self.set_animation_state('success')
                self.root.after(2000, lambda: self.set_animation_state('idle'))
            
            # Add detailed explanations for ALL findings with per-threat actions
            if findings:
                display += self._format_findings_with_explanations(findings)
        else:
            display = str(result)
            findings = []
            self._last_findings = []
            self.set_animation_state('idle')
        self.write_output(label, display)

    def _fail_task(self, error):
        self.set_status('Ready')
        self.set_animation_state('alert')
        self.root.after(2000, lambda: self.set_animation_state('idle'))
        self.write_output('ERROR', str(error))

    def _set_command_input(self, command):
        self.command_entry.delete(0, 'end')
        self.command_entry.insert(0, command)

    def pick_review_file(self):
        path = filedialog.askopenfilename(title='Select file to review')
        if path:
            self._set_command_input(f'r {path}')
            self.run_command()

    def pick_threat_file(self):
        path = filedialog.askopenfilename(title='Select file for threat assessment')
        if path:
            self._set_command_input(f't {path}')
            self.run_command()

    def pick_quarantine_file(self):
        path = filedialog.askopenfilename(title='Select file to quarantine')
        if not path:
            return

        source = Path(path)
        target = self.quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{source.name}"
        target.write_bytes(source.read_bytes())
        source.unlink()
        self.write_output('QUARANTINE', f'[OK] Quarantined: {source.name}\nStored at: {target}')

    def pick_gmail_credentials(self):
        path = filedialog.askopenfilename(title='Select Google OAuth client credentials', filetypes=[('JSON files', '*.json')])
        if path:
            self.gmail_credentials_path = path
            self.write_output('GMAIL', f'[OK] Credentials selected: {path}')

    def open_google_oauth_setup(self):
        webbrowser.open(self.GOOGLE_OAUTH_URL)
        self.write_output(
            'GMAIL',
            f'[OK] Opened Google OAuth setup.\nCredentials page: {self.GOOGLE_OAUTH_URL}\nQuickstart: {self.GMAIL_QUICKSTART_URL}',
        )
        self.avatar_var.set('Stuben opened the Google Cloud page. Add your Gmail as a test user, then download the OAuth JSON.')

    def queue_gmail_auth(self):
        if not self.gmail_credentials_path:
            discovered = GmailIntegration.discover_credentials_candidates()
            if discovered:
                self.gmail_credentials_path = str(discovered[0])
            else:
                self.open_google_oauth_setup()
                self.write_output('GMAIL', 'Use the Open Google OAuth Setup page to download a valid client JSON.')
                return

        self.write_output(
            'GMAIL',
            f'[OK] Gmail auth is ready for: {self.gmail_credentials_path}\nReal Google sign-in requires the OAuth client to be approved for your account.',
        )

    def scan_ai_threats(self):
        """Scan common directories for AI intrusions and malicious code - FAST & SECURE."""
        def action():
            from pathlib import Path
            from concurrent.futures import ThreadPoolExecutor
            
            # Directories to scan for threats
            scan_dirs = [
                Path.home() / "Downloads",
                Path.home() / "Desktop",
                Path.home() / "AppData" / "Local" / "Temp",
                Path(__file__).resolve().parent,
            ]
            
            findings = []
            message_lines = ["AI THREAT SCAN - LIVE SYSTEM ANALYSIS (PARALLELIZED)"]
            
            # Count total files to scan
            total_files = 0
            all_files = []
            for scan_dir in scan_dirs:
                if not scan_dir.exists():
                    continue
                try:
                    for item in sorted(scan_dir.iterdir()):
                        if (item.is_file() and 
                            item.suffix.lower() in self.analyzer.SCANNABLE_SUFFIXES):
                            all_files.append(item)
                            total_files += 1
                except Exception:
                    pass
            
            files_scanned = 0
            
            def scan_single_file(file_path):
                """Scan a single file for threats."""
                nonlocal files_scanned
                try:
                    result = self.analyzer.analyze_file(str(file_path))
                    files_scanned += 1
                    # Update progress every file
                    self.root.after(0, lambda: self.update_progress(files_scanned, total_files))
                    return result
                except Exception:
                    files_scanned += 1
                    self.root.after(0, lambda: self.update_progress(files_scanned, total_files))
                    return []
            
            def scan_directory_parallel(scan_dir):
                """Scan all files in directory using thread pool (parallel file analysis)."""
                dir_findings = []
                if not scan_dir.exists():
                    return dir_findings, 0
                
                files_to_scan = []
                try:
                    for item in sorted(scan_dir.iterdir()):
                        if (item.is_file() and 
                            item.suffix.lower() in self.analyzer.SCANNABLE_SUFFIXES):
                            files_to_scan.append(item)
                except Exception:
                    pass
                
                # Scan files in parallel using thread pool (8 concurrent scans)
                with ThreadPoolExecutor(max_workers=8) as executor:
                    for file_findings in executor.map(scan_single_file, files_to_scan):
                        dir_findings.extend(file_findings)
                
                return dir_findings, len(files_to_scan)
            
            # Scan directories in parallel
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = list(executor.map(scan_directory_parallel, scan_dirs))
            
            # Aggregate results
            total_scanned = 0
            for idx, (scan_dir, (dir_findings, file_count)) in enumerate(zip(scan_dirs, results)):
                findings.extend(dir_findings)
                total_scanned += file_count
                if scan_dir.exists():
                    message_lines.append(f"Scanned: {scan_dir.name} ({file_count} files, {len(dir_findings)} threats)")
            
            message_lines.append(f"Total files scanned: {total_scanned}")
            
            # Final progress update
            self.root.after(0, lambda: self.update_progress(total_files, total_files))
            
            if not findings:
                message_lines.append("\n[OK] No threats detected.")
                summary = "\n".join(message_lines)
                return {"message": summary, "findings": []}
            
            assessment = self.threat_analyst.assess_threat(findings, 'System AI Threat Scan')
            
            summary = "\n".join(message_lines) + "\n" + "\n".join([
                "",
                "THREAT ASSESSMENT",
                f"Level: {assessment['threat_level'].upper()}",
                f"Risk: {assessment['risk_score']}/10",
                f"Type: {assessment['malware_type']}",
                f"Attack Vectors: {', '.join(assessment['attack_vectors']) or 'None'}",
                f"Total Findings: {len(findings)}",
            ])
            
            return {"message": summary, "findings": findings}

        self.queue_task('AI SCAN', 'Scanning system for threats (parallel processing)...', action)

    def show_help(self):
        self.write_output(
            'HELP',
            'r <file>        - Review a single file\nt <file>        - Threat assessment on file\nscan <dir>      - Scan directory\nhtml <path>     - Export HTML report\nAI Threat Scan  - Test AI-focused threats\ngm auth         - Gmail integration\nUse Gmail Connect after adding your Gmail as a test user.',
        )
        self.avatar_var.set('Stuben can review files, assess threats, export HTML reports, and guide Gmail OAuth setup for you.')

    def _review_file_command(self, path):
        findings = self.analyzer.analyze_file(path)
        self.last_review_path = path
        self.update_recommendations(findings)
        self.write_output('RESULT', self.report_generator.generate(findings, 'text'))

    def _threat_file_command(self, path):
        findings = self.analyzer.analyze_file(path)
        self.last_review_path = path
        self.update_recommendations(findings)
        assessment = self.threat_analyst.assess_threat(findings, path)
        self.write_output(
            'THREAT',
            f"THREAT RESULT\nLevel: {assessment['threat_level']}\nRisk: {assessment['risk_score']}/10\nType: {assessment['malware_type']}",
        )

    def _scan_directory_command(self, target):
        findings = self.analyzer.analyze_directory(target, recursive=True)
        self.last_review_path = target
        self.update_recommendations(findings)
        self.write_output('SCAN', self.report_generator.generate(findings, 'text'))

    def run_command(self):
        command = self.command_entry.get().strip()
        if not command:
            return

        self.command_entry.delete(0, 'end')
        self.write_output('COMMAND', command)

        lower = command.lower()
        if lower == 'help':
            self.show_help()
            return
        if lower.startswith('r '):
            self._review_file_command(command[2:].strip())
            return
        if lower.startswith('t '):
            self._threat_file_command(command[2:].strip())
            return
        if lower.startswith('scan '):
            self._scan_directory_command(command[5:].strip())
            return
        if lower.startswith('html '):
            self._export_html_report(command[5:].strip())
            return
        if lower.startswith('gm '):
            self.queue_gmail_auth()
            return

        self.write_output('ERROR', f'Unknown command: {command}')

    def _export_html_report(self, path):
        if not path:
            self.write_output('ERROR', 'Usage: html <file_or_directory_path>')
            return
        try:
            if Path(path).is_file():
                findings = self.analyzer.analyze_file(path)
            else:
                findings = self.analyzer.analyze_directory(path, recursive=True)
            html_content = self.report_generator.generate(findings, 'html')
            output_path = Path(path).parent / f"stuben_report_{Path(path).stem}.html"
            Path(output_path).write_text(html_content, encoding='utf-8')
            self.write_output('HTML EXPORT', f'[OK] Report saved to:\n{output_path}')
        except Exception as e:
            self.write_output('ERROR', f'Failed to export HTML: {str(e)}')

    def run(self):
        self.root.mainloop()


def launch_app():
    app = SecurityDashboard()
    app.run()
