import re
import torch
import numpy as np
from datetime import datetime

def parse_snort_alert(alert_line):
    """
    Parse a single line from snort.alert.fast
    Sample format:
    1/22-11:55:52.200716  [**] [1:1917:6] SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 192.168.1.5:33638 -> 239.255.255.250:1900
    """
    try:
        # Extract protocol and IP information using regex
        protocol_match = re.search(r'\{(\w+)\}', alert_line)
        ip_port_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)', alert_line)

        if protocol_match and ip_port_match:
            # Get protocol
            protocol = protocol_match.group(1)
            # Map protocol to number
            protocol_map = {
                'ICMP': 1,
                'TCP': 6,
                'UDP': 17
            }
            protocol_num = protocol_map.get(protocol, 0)

            # Extract IP addresses and ports
            src_ip = ip_port_match.group(1)
            src_port = int(ip_port_match.group(2))
            dst_ip = ip_port_match.group(3)
            dst_port = int(ip_port_match.group(4))

            # Convert IPs to numeric format (same as training)
            src_ip_num = int(src_ip.replace('.', ''))
            dst_ip_num = int(dst_ip.replace('.', ''))

            # Create feature array in the same format as our training data
            features = np.array([
                src_ip_num,
                src_port,
                dst_ip_num,
                dst_port,
                protocol_num
            ], dtype=np.float32)

            return {
                'features': features,
                'raw_data': {
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol
                }
            }
    except Exception as e:
        print(f"Error parsing alert line: {e}")
        return None

def read_alerts(alert_file_path='/var/log/snort/snort.alert.fast'):
    """Read and parse all alerts from the file"""
    try:
        with open(alert_file_path, 'r') as f:
            alerts = []
            for line in f:
                if line.strip():  # Skip empty lines
                    parsed_alert = parse_snort_alert(line)
                    if parsed_alert:
                        alerts.append(parsed_alert)
            return alerts
    except Exception as e:
        print(f"Error reading alert file: {e}")
        return []

# Test the parser
if __name__ == "__main__":
    # Read alerts
    alerts = read_alerts()

    # Print parsed results
    print(f"\nFound {len(alerts)} alerts")
    if alerts:
        print("\nSample Alert Features:")
        print("Raw Data:", alerts[0]['raw_data'])
        print("Processed Features:", alerts[0]['features'])

        # Example of how these features would be passed to the model
        print("\nFeature Format Ready for Model:")
        features_tensor = torch.FloatTensor(alerts[0]['features']).unsqueeze(0)
        print("Tensor Shape:", features_tensor.shape)
        print("Tensor Values:", features_tensor)
