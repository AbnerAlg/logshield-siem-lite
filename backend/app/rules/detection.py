from datetime import datetime, timedelta
from typing import List
from app.parser.models import LogEntry
from app.rules.models import SecurityAlert

def detect_brute_force(events: List[LogEntry], max_attempts: int = 5, window_seconds: int = 60) -> List[SecurityAlert]:
    """ [Rule 1] Detects Brute Force Attacks. 
        Triggers a HIGH alert if an IP has max_attempts or more failed logins (401/403)
        within a window of window_seconds. """
    
    alerts = []

    # Group events by IP address 
    ip_groups = {}
    for event in events:
        if event.status_code in [401, 403]:
            ip_groups.setdefault(event.ip_address, []).append(event)

    # Analyze time window for each IP
    for ip, ip_events in ip_groups.items():
        #Sort events by timestamp to ensure chronological analysis 
        ip_events.sort(key = lambda x: x.timestamp)

        for i in range(len(ip_events)):
            window_start = ip_events[i].timestamp
            windows_end = window_start + timedelta(seconds = window_seconds)
            
            # Count how many failures occurred in this window 
            failures_in_window = [e for e in ip_events if window_start <= e.timestamp <= windows_end]
            
            if len(failures_in_window) >= max_attempts:
                alerts.append(SecurityAlert(
                    id=f"BRUTE_FORCE_{ip}_{int(window_start.timestamp())}",
                    rule_name="Brute Force Attack Detected",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"IP Triggered {len(failures_in_window)} authentication failures in less than {window_seconds} seconds.",
                    timestamp=datetime.now()
                ))
                break # Avoid duplicating alerts for the same window spike
    return alerts
    

def detect_suspicious_paths(events: List[LogEntry]) -> List[SecurityAlert]:
    """ [RULE 2] Detects Admin Path Discovery
        Triggers a CRITICAL alert if any IP tries to access high-risk administrative paths.
    """
    alerts=[]

    # High-risk targets common in recon phases 
    suspicious_keywords = ["/admin", "/wp_admin", "/wp-login.php", "/config", ".env"]

    for event in events:
        path_lower = event.path.lower()
        if any(keyword in path_lower for keyword in suspicious_keywords):
            alerts.append(SecurityAlert(
                id=f"SUSPICIOUS_PATH_{event.ip_address}_{int(event.timestamp.timestamp())}",
                rule_name="Unauthorized Admin Path Discovery",
                severity="CRITICAL",
                source_ip=event.ip_address,
                description=f"IP attempted to access a restricted administrative path: '{event.path}'",
                timestamp=datetime.now(),
                triggered_by_status=event.status_code
            ))
    return alerts

def analyze_security_threats(events: List[LogEntry]) -> List[SecurityAlert]:
    """ Main orchestrator that runs all compiled security rules against parsed logs.
    """        
    all_alerts=[]
    all_alerts.extend(detect_brute_force(events))
    all_alerts.extend(detect_suspicious_paths(events))
    return all_alerts

# Local testing block 
if __name__ == "__main__":
    from pathlib import Path
    from app.parser.log_parser import parse_log_file

    base_dir = Path(__file__).resolve().parent.parent.parent
    mock_log_path = base_dir / "logs" / "mock_access.log"

    print("[*] Parsing logs for security evaluation...")
    parsed_events = parse_log_file(mock_log_path)

    print("[*] Running Security Rule Engine...")
    detected_alerts = analyze_security_threats(parsed_events)

    print(f"\n[*] Analysis Complete: Found {len(detected_alerts)} security alerts.")
    print("-" * 60)

    for alert in detected_alerts:
        print(f"[{alert.severity}] - Rule: {alert.rule_name}")
        print(f"    Target IP: {alert.source_ip}")
        print(f"    Details: {alert.description}\n")
