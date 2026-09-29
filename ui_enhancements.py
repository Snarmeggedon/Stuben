"""
UI/UX enhancements for Stuben dashboard.
"""


class UIThemeManager:
    """Manage UI themes and styling for Stuben."""
    
    # Dark theme (default)
    DARK_THEME = {
        "bg_primary": "#0b1220",       # Main background
        "bg_secondary": "#111827",      # Secondary background
        "bg_tertiary": "#1f2937",       # Tertiary background
        "bg_hover": "#334155",          # Hover state
        "border": "#374151",            # Borders/dividers
        
        "fg_primary": "#f9fafb",        # Primary text
        "fg_secondary": "#e5e7eb",      # Secondary text
        "fg_tertiary": "#d1d5db",       # Tertiary text
        
        "accent_critical": "#fbbf24",   # Critical/warning yellow
        "accent_danger": "#f87171",     # Danger red
        "accent_info": "#60a5fa",       # Info blue
        "accent_success": "#4ade80",    # Success green
    }
    
    # Light theme (alternative)
    LIGHT_THEME = {
        "bg_primary": "#f9fafb",
        "bg_secondary": "#f3f4f6",
        "bg_tertiary": "#e5e7eb",
        "bg_hover": "#d1d5db",
        "border": "#d1d5db",
        
        "fg_primary": "#111827",
        "fg_secondary": "#374151",
        "fg_tertiary": "#6b7280",
        
        "accent_critical": "#d97706",
        "accent_danger": "#dc2626",
        "accent_info": "#2563eb",
        "accent_success": "#059669",
    }
    
    CURRENT_THEME = DARK_THEME
    
    @staticmethod
    def get_color(name):
        """Get color from current theme."""
        return UIThemeManager.CURRENT_THEME.get(name, "#000000")
    
    @staticmethod
    def switch_theme(theme_name):
        """Switch to a different theme."""
        if theme_name == "light":
            UIThemeManager.CURRENT_THEME = UIThemeManager.LIGHT_THEME
        elif theme_name == "dark":
            UIThemeManager.CURRENT_THEME = UIThemeManager.DARK_THEME


class UIComponents:
    """Reusable UI component builders for Stuben."""
    
    @staticmethod
    def create_threat_card_style(severity):
        """Get styling for a threat card based on severity."""
        colors = {
            "critical": UIThemeManager.get_color("accent_critical"),
            "high": UIThemeManager.get_color("accent_danger"),
            "medium": UIThemeManager.get_color("accent_info"),
            "low": UIThemeManager.get_color("accent_success"),
        }
        return {
            "fg": colors.get(severity.lower(), UIThemeManager.get_color("fg_primary")),
            "bg": UIThemeManager.get_color("bg_secondary"),
        }
    
    @staticmethod
    def create_button_style(variant="default"):
        """Get styling for buttons."""
        styles = {
            "default": {
                "bg": UIThemeManager.get_color("bg_secondary"),
                "fg": UIThemeManager.get_color("fg_primary"),
                "activebackground": UIThemeManager.get_color("bg_hover"),
            },
            "success": {
                "bg": UIThemeManager.get_color("accent_success"),
                "fg": "#ffffff",
                "activebackground": UIThemeManager.get_color("accent_success"),
            },
            "danger": {
                "bg": UIThemeManager.get_color("accent_danger"),
                "fg": "#ffffff",
                "activebackground": UIThemeManager.get_color("accent_danger"),
            },
            "primary": {
                "bg": UIThemeManager.get_color("accent_info"),
                "fg": "#ffffff",
                "activebackground": UIThemeManager.get_color("accent_info"),
            },
        }
        return styles.get(variant, styles["default"])
    
    @staticmethod
    def format_threat_summary(threat_score, risk_level, findings_count):
        """Format threat summary for display."""
        emoji_map = {
            "CRITICAL": "⛔",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }
        emoji = emoji_map.get(risk_level, "❓")
        return f"{emoji} Score: {threat_score:.1f}/10 • {risk_level} • {findings_count} findings"


class AccessibilityOptions:
    """Accessibility features for Stuben."""
    
    FONT_SIZES = {
        "small": 8,
        "default": 9,
        "large": 11,
        "xlarge": 13,
    }
    
    CONTRAST_LEVELS = {
        "normal": 1.0,
        "high": 1.5,
        "extra_high": 2.0,
    }
    
    current_font_size = "default"
    current_contrast = "normal"
    
    @staticmethod
    def get_font_size(level="default"):
        """Get font size for accessibility level."""
        return AccessibilityOptions.FONT_SIZES.get(level, 9)
    
    @staticmethod
    def set_font_size(level):
        """Set global font size level."""
        AccessibilityOptions.current_font_size = level
    
    @staticmethod
    def adjust_color_contrast(color, multiplier=1.5):
        """Adjust color contrast for accessibility."""
        # Convert hex to RGB
        hex_color = color.lstrip("#")
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        # Increase contrast by adjusting brightness
        factor = multiplier
        r = min(255, int(r * factor))
        g = min(255, int(g * factor))
        b = min(255, int(b * factor))
        
        return f"#{r:02x}{g:02x}{b:02x}"
