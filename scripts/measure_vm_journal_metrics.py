import os
import subprocess
import time

def measure():
    # 1. Total journal disk usage
    res_usage = subprocess.check_output(['journalctl', '--disk-usage']).decode().strip()
    print('Disk Usage:', res_usage)

    # 2. Inspect journal files in /var/log/journal
    jpath = '/var/log/journal'
    jfiles = []
    total_bytes = 0
    if os.path.exists(jpath):
        for root, dirs, files in os.walk(jpath):
            for f in files:
                fp = os.path.join(root, f)
                sz = os.path.getsize(fp)
                total_bytes += sz
                jfiles.append((f, sz))

    print(f"Total journal files: {len(jfiles)}, Total bytes: {total_bytes} ({total_bytes / (1024*1024):.2f} MB)")
    for f, sz in sorted(jfiles, key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {f:45}: {sz / (1024*1024):.2f} MB")

    # 3. Measure event velocity over last 1 hour
    now = time.time()
    one_hour_ago = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now - 3600))
    cmd = ['journalctl', '--since', one_hour_ago, '--output=json']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = p.stdout.readlines()
    p.wait()
    total_system_events = len(lines)
    raw_size = sum(len(l) for l in lines)
    avg_size = raw_size / max(total_system_events, 1)

    print(f"\nEmpirical Measurements (Last 1 Hour):")
    print(f"  - Total System Journal Entries: {total_system_events}")
    print(f"  - Total Raw Payload: {raw_size} bytes ({raw_size/1024:.2f} KB)")
    print(f"  - Average Entry Size: {avg_size:.2f} bytes")

    # 4. Measure security-relevant events (SSH, auth, PAM, sudo)
    cmd_sec = ['journalctl', '--since', one_hour_ago, '-u', 'ssh', '-u', 'sudo', '--output=json']
    p_sec = subprocess.Popen(cmd_sec, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines_sec = p_sec.stdout.readlines()
    p_sec.wait()
    sec_events = len(lines_sec)
    sec_raw_size = sum(len(l) for l in lines_sec)
    avg_sec_size = sec_raw_size / max(sec_events, 1)

    print(f"\nSecurity-Relevant Telemetry (SSH, PAM, Sudo - Last 1 Hour):")
    print(f"  - Security Event Count: {sec_events}")
    print(f"  - Security Raw Payload: {sec_raw_size} bytes ({sec_raw_size/1024:.2f} KB)")
    print(f"  - Average Security Event Size: {avg_sec_size:.2f} bytes")

    # 5. Disk capacity and retention headroom
    statvfs = os.statvfs('/var/log/journal')
    free_bytes = statvfs.f_bavail * statvfs.f_frsize
    total_fs_bytes = statvfs.f_blocks * statvfs.f_frsize
    default_max_use = min(total_fs_bytes * 0.10, 4 * 1024 * 1024 * 1024)
    headroom_bytes = max(0, default_max_use - total_bytes)

    print(f"\nJournald Capacity Analysis:")
    print(f"  - Filesystem Total: {total_fs_bytes / (1024*1024*1024):.2f} GB")
    print(f"  - Filesystem Free: {free_bytes / (1024*1024*1024):.2f} GB")
    print(f"  - Default SystemMaxUse (10% of FS): {default_max_use / (1024*1024):.2f} MB")
    print(f"  - Current Journal Disk Usage: {total_bytes / (1024*1024):.2f} MB")
    print(f"  - Effective Headroom Before Rotation: {headroom_bytes / (1024*1024):.2f} MB")

    # 6. Retention Duration Formulas
    # Scenario A: Normal Operations
    hourly_rate_bytes = max(raw_size, 50 * 1024) # at least 50 KB/hr
    hours_normal = headroom_bytes / hourly_rate_bytes
    days_normal = hours_normal / 24.0

    # Scenario B: Active Attack Simulation (100 auth attempts per second)
    # 100 events/sec * 1200 bytes/event = 120,000 bytes/sec (~117 KB/sec or 412 MB/hour)
    extreme_bytes_per_sec = 100 * 1200 # 100 events/s * 1.2 KB
    hours_extreme = headroom_bytes / (extreme_bytes_per_sec * 3600)

    print(f"\nCalculated Retention Window:")
    print(f"  [Scenario A: Normal Operations (~{hourly_rate_bytes/1024:.1f} KB/hr)]")
    print(f"    - Safe Retention Duration: {days_normal:.1f} days ({hours_normal:.1f} hours)")
    print(f"  [Scenario B: Extreme Attack (100 auth attempts/sec = {extreme_bytes_per_sec/1024:.1f} KB/s)]")
    print(f"    - Safe Retention Duration: {hours_extreme:.2f} hours ({hours_extreme*60:.1f} minutes)")

if __name__ == '__main__':
    measure()

