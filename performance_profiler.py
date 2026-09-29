"""
Performance profiling and optimization utilities for Stuben.
"""
import time
from pathlib import Path
from analyzer import CodeAnalyzer


class PerformanceProfiler:
    """Profile scanning performance and identify bottlenecks."""
    
    def __init__(self):
        self.analyzer = CodeAnalyzer()
        self.metrics = {
            "files_scanned": 0,
            "directories_scanned": 0,
            "total_time": 0,
            "avg_file_time": 0,
            "patterns_matched": 0,
        }
    
    def profile_file_scan(self, file_path):
        """Profile scanning a single file."""
        start = time.time()
        findings = self.analyzer.analyze_file(str(file_path))
        elapsed = time.time() - start
        
        return {
            "file": str(file_path),
            "time_ms": elapsed * 1000,
            "findings": len(findings),
        }
    
    def profile_directory_scan(self, directory, recursive=False):
        """Profile scanning a directory."""
        start = time.time()
        findings = self.analyzer.analyze_directory(str(directory), recursive=recursive)
        elapsed = time.time() - start
        
        file_count = len(list(Path(directory).rglob("*.py" if recursive else "*.py")))
        if not recursive:
            file_count = len(list(Path(directory).glob("*.py")))
        
        return {
            "directory": str(directory),
            "time_seconds": elapsed,
            "files_scanned": file_count,
            "findings": len(findings),
            "avg_ms_per_file": (elapsed / file_count * 1000) if file_count > 0 else 0,
        }
    
    def get_optimization_recommendations(self, profile_data):
        """Provide optimization recommendations based on profiling data."""
        recommendations = []
        
        if profile_data["avg_ms_per_file"] > 100:
            recommendations.append("🔴 Slow file scanning (>100ms/file): Consider increasing thread pool size or reducing pattern count.")
        elif profile_data["avg_ms_per_file"] > 50:
            recommendations.append("🟡 Moderate file scanning speed (50-100ms/file): Can be optimized by pattern caching.")
        else:
            recommendations.append("🟢 Fast file scanning (<50ms/file): Excellent performance!")
        
        return recommendations


if __name__ == "__main__":
    import sys
    
    profiler = PerformanceProfiler()
    
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if Path(path).is_file():
            result = profiler.profile_file_scan(path)
        else:
            result = profiler.profile_directory_scan(path, recursive=True)
        
        print("PERFORMANCE PROFILE")
        print("=" * 60)
        for key, value in result.items():
            print(f"{key:.<40} {value}")
        
        if "avg_ms_per_file" in result:
            recs = profiler.get_optimization_recommendations(result)
            print("\nRECOMMENDATIONS")
            print("=" * 60)
            for rec in recs:
                print(rec)
    else:
        print("Usage: python performance_profiler.py <file_or_directory>")
