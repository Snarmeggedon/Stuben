"""
Analytics and dashboard for Stuben security operations.
"""
from datetime import datetime, timedelta
from action_history import ActionHistory


class StubensAnalyticsDashboard:
    """Generate analytics and insights from scan history."""
    
    def __init__(self):
        self.history = ActionHistory()
    
    def get_scan_statistics(self):
        """Get statistics about scans performed."""
        actions = self.history.get_recent_actions(limit=1000)
        scans = [a for a in actions if a.get("type") == "scan_executed"]
        
        if not scans:
            return {
                "total_scans": 0,
                "total_files": 0,
                "total_findings": 0,
                "avg_findings_per_scan": 0,
                "most_recent_scan": None,
            }
        
        total_files = sum(s.get("files_scanned", 0) for s in scans)
        total_findings = sum(s.get("findings_detected", 0) for s in scans)
        
        return {
            "total_scans": len(scans),
            "total_files": total_files,
            "total_findings": total_findings,
            "avg_findings_per_scan": total_findings / len(scans) if scans else 0,
            "most_recent_scan": scans[0].get("timestamp") if scans else None,
            "avg_scan_time_seconds": sum(s.get("duration_seconds", 0) for s in scans) / len(scans) if scans else 0,
        }
    
    def get_threat_trends(self):
        """Identify emerging threat patterns."""
        actions = self.history.get_recent_actions(limit=1000)
        threats = [a for a in actions if a.get("type") == "threat_found"]
        
        threat_counts = {}
        for threat in threats:
            pattern = threat.get("threat_pattern", "unknown")
            threat_counts[pattern] = threat_counts.get(pattern, 0) + 1
        
        # Sort by frequency
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "total_unique_threats": len(threat_counts),
            "top_threats": sorted_threats[:10],
            "threat_frequency": dict(sorted_threats),
        }
    
    def get_action_effectiveness(self):
        """Analyze effectiveness of recommended actions."""
        actions = self.history.get_recent_actions(limit=1000)
        action_logs = [a for a in actions if a.get("type") == "action_taken"]
        
        if not action_logs:
            return {
                "total_actions_taken": 0,
                "successful_actions": 0,
                "success_rate": 0,
            }
        
        successful = sum(1 for a in action_logs if a.get("success", False))
        
        return {
            "total_actions_taken": len(action_logs),
            "successful_actions": successful,
            "success_rate": (successful / len(action_logs) * 100) if action_logs else 0,
            "recent_actions": [a for a in action_logs[-5:]][::-1],
        }
    
    def get_user_engagement(self):
        """Measure user engagement with Stuben."""
        actions = self.history.get_recent_actions(limit=1000)
        
        responses = [a for a in actions if a.get("type") == "user_response"]
        actions_taken = [a for a in actions if a.get("type") == "action_taken"]
        
        return {
            "user_questions_answered": len(responses),
            "recommended_actions_executed": len(actions_taken),
            "engagement_score": (len(responses) + len(actions_taken)) / max(1, len([a for a in actions if a.get("type") == "scan_executed"])),
        }
    
    def generate_daily_report(self):
        """Generate a daily security report."""
        stats = self.get_scan_statistics()
        trends = self.get_threat_trends()
        effectiveness = self.get_action_effectiveness()
        engagement = self.get_user_engagement()
        
        report = {
            "report_date": datetime.now().isoformat(),
            "statistics": stats,
            "trends": trends,
            "effectiveness": effectiveness,
            "engagement": engagement,
        }
        
        return report
    
    def format_dashboard_summary(self):
        """Format dashboard summary for display."""
        stats = self.get_scan_statistics()
        trends = self.get_threat_trends()
        
        lines = [
            "📊 STUBEN SECURITY DASHBOARD",
            "=" * 60,
            f"\n📈 SCAN STATISTICS",
            f"  Total Scans Run:        {stats['total_scans']}",
            f"  Files Scanned:          {stats['total_files']}",
            f"  Threats Detected:       {stats['total_findings']}",
            f"  Avg. Threats/Scan:      {stats['avg_findings_per_scan']:.1f}",
            f"  Avg. Scan Time:         {stats['avg_scan_time_seconds']:.2f}s",
        ]
        
        if trends["total_unique_threats"] > 0:
            lines.append(f"\n🎯 TOP THREATS (Last 1000 events)")
            for threat, count in trends["top_threats"][:5]:
                lines.append(f"  • {threat:.<40} {count} detected")
        
        engagement = self.get_user_engagement()
        lines.append(f"\n👤 USER ENGAGEMENT")
        lines.append(f"  Questions Answered:     {engagement['user_questions_answered']}")
        lines.append(f"  Actions Executed:       {engagement['recommended_actions_executed']}")
        lines.append(f"  Engagement Score:       {engagement['engagement_score']:.2f}")
        
        return "\n".join(lines)
    
    def export_analytics_report(self, output_file="analytics_report.json"):
        """Export full analytics as JSON."""
        import json
        from pathlib import Path
        
        report = self.generate_daily_report()
        output_path = Path(__file__).resolve().parent / output_file
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(output_path)


if __name__ == "__main__":
    dashboard = StubensAnalyticsDashboard()
    print(dashboard.format_dashboard_summary())
