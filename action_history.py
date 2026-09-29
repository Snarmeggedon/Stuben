import json
from datetime import datetime
from pathlib import Path


class ActionHistory:
    """Track user actions, recommendations, and security decisions."""
    
    def __init__(self, history_file="action_history.json"):
        self.history_file = Path(__file__).resolve().parent / history_file
        self.actions = self._load_history()
    
    def _load_history(self):
        """Load action history from disk."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def _save_history(self):
        """Save action history to disk."""
        with open(self.history_file, 'w') as f:
            json.dump(self.actions, f, indent=2)
    
    def log_action(self, action_type, threat_pattern, action_name, details="", success=True):
        """Log a security action taken by the user."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": action_type,  # "threat_found", "action_taken", "question_answered", "recommendation_accepted"
            "threat_pattern": threat_pattern,
            "action": action_name,
            "details": details,
            "success": success,
        }
        self.actions.append(entry)
        self._save_history()
        return entry
    
    def log_scan(self, scan_type, file_count, findings_count, duration_seconds):
        """Log a scan execution."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "scan_executed",
            "scan_type": scan_type,
            "files_scanned": file_count,
            "findings_detected": findings_count,
            "duration_seconds": duration_seconds,
        }
        self.actions.append(entry)
        self._save_history()
        return entry
    
    def log_user_response(self, threat_pattern, question, user_answer):
        """Log user's response to Stuben's threat question."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "user_response",
            "threat_pattern": threat_pattern,
            "question": question,
            "answer": user_answer,
        }
        self.actions.append(entry)
        self._save_history()
        return entry
    
    def get_recent_actions(self, limit=20):
        """Get recent actions in reverse chronological order."""
        return self.actions[-limit:][::-1]
    
    def get_threat_history(self, threat_pattern):
        """Get all actions related to a specific threat pattern."""
        return [a for a in self.actions if a.get("threat_pattern") == threat_pattern]
    
    def get_action_summary(self):
        """Get summary statistics of actions taken."""
        if not self.actions:
            return {
                "total_actions": 0,
                "scans_run": 0,
                "threats_found": 0,
                "actions_taken": 0,
                "user_responses": 0,
            }
        
        return {
            "total_actions": len(self.actions),
            "scans_run": len([a for a in self.actions if a.get("type") == "scan_executed"]),
            "threats_found": len([a for a in self.actions if a.get("type") == "threat_found"]),
            "actions_taken": len([a for a in self.actions if a.get("type") == "action_taken"]),
            "user_responses": len([a for a in self.actions if a.get("type") == "user_response"]),
        }
    
    def export_report(self, output_file="action_report.json"):
        """Export full action history as a report."""
        report = {
            "exported": datetime.now().isoformat(),
            "summary": self.get_action_summary(),
            "actions": self.actions,
        }
        output_path = Path(__file__).resolve().parent / output_file
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        return str(output_path)
