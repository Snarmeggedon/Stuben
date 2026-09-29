"""
Real-time system monitoring during threat scans.
Tracks CPU, memory, network, and file I/O.
"""
import psutil
import threading
import time
from collections import deque
from datetime import datetime


class SystemMonitor:
    """Monitor system resources during scanning."""
    
    def __init__(self, sample_interval=1.0, max_samples=60):
        self.sample_interval = sample_interval
        self.max_samples = max_samples
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Store metrics
        self.cpu_samples = deque(maxlen=max_samples)
        self.memory_samples = deque(maxlen=max_samples)
        self.network_samples = deque(maxlen=max_samples)
        self.io_samples = deque(maxlen=max_samples)
        self.timestamps = deque(maxlen=max_samples)
        
        # Baseline (for comparison)
        self.baseline_cpu = None
        self.baseline_memory = None
    
    def start_monitoring(self):
        """Start background monitoring thread."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.baseline_cpu = psutil.cpu_percent(interval=0.1)
        self.baseline_memory = psutil.virtual_memory().percent
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.is_monitoring:
            try:
                self.timestamps.append(datetime.now())
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self.cpu_samples.append(cpu_percent)
                
                # Memory usage
                mem_info = psutil.virtual_memory()
                self.memory_samples.append(mem_info.percent)
                
                # Network I/O
                net_io = psutil.net_io_counters()
                self.network_samples.append({
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                })
                
                # Disk I/O
                try:
                    disk_io = psutil.disk_io_counters()
                    self.io_samples.append({
                        "read_bytes": disk_io.read_bytes,
                        "write_bytes": disk_io.write_bytes,
                        "read_count": disk_io.read_count,
                        "write_count": disk_io.write_count,
                    })
                except (AttributeError, OSError):
                    # Disk I/O not available on all systems
                    self.io_samples.append(None)
                
                time.sleep(self.sample_interval)
            except Exception as e:
                print(f"Monitoring error: {e}")
                break
    
    def get_current_stats(self):
        """Get latest system statistics."""
        if not self.cpu_samples:
            return None
        
        return {
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": self.cpu_samples[-1] if self.cpu_samples else 0,
            "memory_percent": self.memory_samples[-1] if self.memory_samples else 0,
            "cpu_available_percent": 100 - (self.cpu_samples[-1] if self.cpu_samples else 0),
            "memory_available_gb": psutil.virtual_memory().available / (1024**3),
            "memory_total_gb": psutil.virtual_memory().total / (1024**3),
        }
    
    def get_average_stats(self):
        """Get average statistics during monitoring period."""
        if not self.cpu_samples:
            return None
        
        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0
        avg_memory = sum(self.memory_samples) / len(self.memory_samples) if self.memory_samples else 0
        
        return {
            "avg_cpu_percent": avg_cpu,
            "avg_memory_percent": avg_memory,
            "peak_cpu_percent": max(self.cpu_samples) if self.cpu_samples else 0,
            "peak_memory_percent": max(self.memory_samples) if self.memory_samples else 0,
            "samples_collected": len(self.cpu_samples),
        }
    
    def get_network_stats(self):
        """Get network activity statistics."""
        if len(self.network_samples) < 2:
            return {"bytes_per_second": 0, "packets_per_second": 0}
        
        first = self.network_samples[0]
        last = self.network_samples[-1]
        
        bytes_diff = (last["bytes_sent"] + last["bytes_recv"]) - \
                     (first["bytes_sent"] + first["bytes_recv"])
        packets_diff = (last["packets_sent"] + last["packets_recv"]) - \
                       (first["packets_sent"] + first["packets_recv"])
        
        elapsed = len(self.network_samples) * self.sample_interval
        
        return {
            "bytes_per_second": bytes_diff / elapsed if elapsed > 0 else 0,
            "packets_per_second": packets_diff / elapsed if elapsed > 0 else 0,
            "total_bytes_transferred": bytes_diff,
        }
    
    def get_io_stats(self):
        """Get disk I/O statistics."""
        if len(self.io_samples) < 2 or self.io_samples[0] is None:
            return {"read_bytes_per_second": 0, "write_bytes_per_second": 0}
        
        first = self.io_samples[0]
        last = self.io_samples[-1]
        
        if first is None or last is None:
            return {"read_bytes_per_second": 0, "write_bytes_per_second": 0}
        
        read_diff = last["read_bytes"] - first["read_bytes"]
        write_diff = last["write_bytes"] - first["write_bytes"]
        
        elapsed = len(self.io_samples) * self.sample_interval
        
        return {
            "read_bytes_per_second": read_diff / elapsed if elapsed > 0 else 0,
            "write_bytes_per_second": write_diff / elapsed if elapsed > 0 else 0,
            "total_read_bytes": read_diff,
            "total_write_bytes": write_diff,
        }
    
    def format_status_display(self):
        """Format system status for UI display."""
        stats = self.get_current_stats()
        if not stats:
            return "No monitoring data"
        
        lines = [
            f"🖥️  CPU: {stats['cpu_percent']:.1f}% used ({stats['cpu_available_percent']:.1f}% available)",
            f"💾 Memory: {stats['memory_percent']:.1f}% used ({stats['memory_available_gb']:.1f}GB available)",
        ]
        
        net = self.get_network_stats()
        if net["bytes_per_second"] > 0:
            lines.append(f"🌐 Network: {net['bytes_per_second']/1024:.1f} KB/s")
        
        io = self.get_io_stats()
        if io["read_bytes_per_second"] > 0 or io["write_bytes_per_second"] > 0:
            read_mb = io["read_bytes_per_second"] / (1024**2)
            write_mb = io["write_bytes_per_second"] / (1024**2)
            lines.append(f"💿 Disk I/O: Read {read_mb:.1f} MB/s, Write {write_mb:.1f} MB/s")
        
        return "\n".join(lines)
    
    def format_summary(self):
        """Format complete monitoring summary."""
        avg_stats = self.get_average_stats()
        net_stats = self.get_network_stats()
        io_stats = self.get_io_stats()
        
        if not avg_stats:
            return "No monitoring data available"
        
        lines = [
            "📊 SCAN SYSTEM MONITORING SUMMARY",
            "=" * 60,
            f"\n⏱️ Duration: {avg_stats['samples_collected'] * self.sample_interval:.1f} seconds",
            f"\n🖥️  CPU USAGE",
            f"  Average: {avg_stats['avg_cpu_percent']:.1f}%",
            f"  Peak: {avg_stats['peak_cpu_percent']:.1f}%",
            f"\n💾 MEMORY USAGE",
            f"  Average: {avg_stats['avg_memory_percent']:.1f}%",
            f"  Peak: {avg_stats['peak_memory_percent']:.1f}%",
            f"\n🌐 NETWORK ACTIVITY",
            f"  Data transferred: {net_stats['total_bytes_transferred'] / (1024**2):.2f} MB",
            f"  Peak rate: {net_stats['bytes_per_second'] / (1024**2):.2f} MB/s",
            f"\n💿 DISK I/O",
            f"  Total read: {io_stats['total_read_bytes'] / (1024**2):.2f} MB",
            f"  Total write: {io_stats['total_write_bytes'] / (1024**2):.2f} MB",
        ]
        
        return "\n".join(lines)


if __name__ == "__main__":
    monitor = SystemMonitor()
    monitor.start_monitoring()
    
    print("Monitoring for 10 seconds...")
    for i in range(10):
        time.sleep(1)
        print(monitor.format_status_display())
        print()
    
    monitor.stop_monitoring()
    print(monitor.format_summary())
