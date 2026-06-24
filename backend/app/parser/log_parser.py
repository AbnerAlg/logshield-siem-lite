import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from app.parser.models import LogEntry

LOG_REGEX = r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
# Format: IP - - [DATE] "METHOD ROUT VERSION_HTTP" STATE SIZE
# For example: 192.168.1.10 - - [23/Jun/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 532


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parses a single raw text line and returns a structured LogEntry objects. 
       Return None if the line does not match the expected security format."""
    
    match = re.match(LOG_REGEX, line)
    if not match:
        return None
    
    # This function convert the groups of the regular expretion in a dictionary
    data = match.groupdict()

    raw_time = data['timestamp'].split()[0]
    clean_timestamp = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S")

    return LogEntry(
        ip_address=data['ip'],
        timestamp=clean_timestamp,
        method=data['method'],
        path=data['path'],
        status_code=int(data['status']),
        size=int(data['size'])
    )
    # The regular expresion returns 'status' and 'size' as text (ex: "401", "500")

def parse_log_file(file_path: Path) -> List[LogEntry]:
    """Reads a local file entirely and parses every single line."""
    
    parsed_entries = []
    
    if not file_path.exists():
        print(f"[-] Error: File not found at {file_path}")
        return parsed_entries 
    
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file: 
            entry = parse_log_line(line.strip())
            if entry:
                parsed_entries.append(entry)
    return parsed_entries

# Local execution block for testing in Windows enviroments
if __name__ == "__main__":
    # Pathlib handles cross_platform path diferences seamlessly
    base_dir = Path(__file__).resolve().parent.parent.parent
    mock_log_path = base_dir / "logs" / "mock_access.log"

    print(f"[*] Scanning log files from {mock_log_path}")
    results = parse_log_file(mock_log_path)

    print(f"[*] Success: Parsed {len(results)} events.")
    for event in results:
        print(f"IP: {event.ip_address} | Path: {event.path} | Status: {event.status_code} ")


