import masscan

def scan_open_ports(target):
    # Create a new Masscan object
    scanner = masscan.PortScanner()

    # Perform port scan on the target
    scanner.scan(target, ports='1-65535', arguments='--rate=10000')

    # Extract open ports
    open_ports = []
    for result in scanner.scan_result['scan']:
        for port in scanner.scan_result['scan'][result]['tcp']:
            open_ports.append(port['portid'])

    return open_ports

# Example usage
target = '192.168.1.109'
open_ports = scan_open_ports(target)
print("Open ports:", open_ports)