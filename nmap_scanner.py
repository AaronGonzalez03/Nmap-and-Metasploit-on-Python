import nmap
import ipaddress

scanner = nmap.PortScanner()

print("#=========================#")
print("Welcome to the Nmap Scanner")
print("#=========================#")

# Get target IP address from the user
while True:
    ip_address = input("Please enter the IP address you want to scan: ")
    try:
        ipaddress.ip_address(ip_address)
        print(f"Valid IP address: {ip_address}")
        break
    except ValueError:
        print("Invalid IP address. Please ensure it is in the correct format. Try again.")


# Create the arguments for the scan based on user preferences
def scan_arguments(port_range, detect_service_version, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity):
    args = f"{port_range} {detect_service_version} {scan_velocity} {os_detection} {victims_machine_state} {ports_state} {verbosity}"
    return args

# Get port range from user
while True:
    port_range = input("Enter port range (example: 1-1000) or 'ALL' for all ports: ")
    if port_range.strip().upper() == 'ALL':
        port_range = '-p-'
        break
    else:
        try:
            start, end = map(int, port_range.split('-'))
            if start >= 1 and end <= 65535 and start <= end:
                port_range = f'-p {start}-{end}'
                break
            else:
                print("Invalid range. Ports must be between 1 and 65535, and start <= end.")
        except ValueError:
            print("Invalid format. Use 'start-end' (example: 1-1000) or 'ALL'.")


# Service version detection option
while True:
    service_version = input("Do you want to enable service and version detection? (yes/no): ").strip().lower()
    if service_version == 'yes':
        detect_service_version = '-sV'
        break
    elif service_version == 'no':
        detect_service_version = ''
        break
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")


# Get scan velocity from user
while True:
    scan_velocity = input("Select scan velocity between 1-5. 1 is the slowest but the quietest and 5 is the fastest but the loudest: ")
    if scan_velocity in ['1', '2', '3', '4', '5']:
        scan_velocity = f"-T{scan_velocity}"
        break
    else:
        print("Invalid input. Please enter a number between 1 and 5.")


# OS detection option
while True:
    os_detection = input("Do you want to enable OS detection? (yes/no): ").strip().lower()
    if os_detection == 'yes':
        os_detection = '-O'
        break
    elif os_detection == 'no':
        os_detection = ''
        break
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")


# Victim's machine state option - BUG FIX: initialize variable in both cases
while True:
    victims_machine_state = input("Do you want to know if the machine is up or down? (yes/no): ").strip().lower()
    if victims_machine_state == 'yes':
        victims_machine_state = ''  # Nmap by default pings to check if host is up
        break
    elif victims_machine_state == 'no':
        victims_machine_state = '-Pn'  # Skip host discovery
        break
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")


# Filter by open ports option
while True:
    ports_state = input("Do you want to filter results by open ports only? (yes/no): ").strip().lower()
    if ports_state == 'yes':
        ports_state = '--open'
        break
    elif ports_state == 'no':
        ports_state = ''
        break
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")


# Get verbosity level from user
while True:
    verbosity = input("How much information do you want during the scan? (low/medium/high): ").strip().lower()
    if verbosity == 'low':
        verbosity = '-v'
        break
    elif verbosity == 'medium':
        verbosity = '-vv'
        break
    elif verbosity == 'high':
        verbosity = '-vvv'
        break
    else:
        print("Invalid input. Please enter 'low', 'medium' or 'high'.")


print(f"\nFinal scan arguments:")
print(f"  IP to scan: {ip_address}")
print(f"  Scan arguments: {scan_arguments(port_range, detect_service_version, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity)}")
print(f"\nFinal scan command: nmap {scan_arguments(port_range, detect_service_version, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity)} {ip_address}\n")


while True:
    continue_scan = input("Do you want to proceed with the scan? (yes/no): ").strip().lower()
    if continue_scan == 'yes':
        print(f"\nScanning {ip_address}...\n")
        break
    elif continue_scan == 'no':
        print("Scan aborted by user.")
        print("Exited the program.")
        exit()
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")

print(f"\nScanning {ip_address}...")

# Execute the scan and save the results
results = scanner.scan(ip_address, arguments=scan_arguments(port_range, detect_service_version, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity))

# SHOW RESULTS
# This loop iterates over each scanned host (usually just one)
for ip_address in scanner.all_hosts():
    print('='*60)
    print(f'IP Address: {ip_address} ({scanner[ip_address].hostname()})')
    print(f'State: {scanner[ip_address].state()}')
    
    # Display OS information if available
    if 'osmatch' in scanner[ip_address] and scanner[ip_address]['osmatch']:
        print(f'OS: {scanner[ip_address]["osmatch"][0]["name"]} (accuracy: {scanner[ip_address]["osmatch"][0]["accuracy"]}%)')
    
    print('='*60)
    
    # This loop iterates over each protocol found (tcp, udp, etc.)
    for proto in scanner[ip_address].all_protocols():
        print(f'\nProtocol: {proto}')
        print('-'*60)

        # Get list of ports and sort them
        lport = list(scanner[ip_address][proto].keys())
        lport.sort()
        
        # This loop iterates over each port found in this protocol
        for port in lport:
            port_info = scanner[ip_address][proto][port]
            
            # Extract port information
            service = port_info.get('name', 'unknown')
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            
            # Build version string in a clean way
            # If both product and version exist, show both separated by space
            # If only one exists, show that one
            # If neither exists, show "unknown"
            if product and version:
                version_info = f"{product} {version}"
            elif product:
                version_info = product
            elif version:
                version_info = version
            else:
                version_info = "unknown"
            
            # Clean and consistent output format
            # IMPORTANT: This print MUST be inside the for port loop
            print(f"port: {port:<8} state: {port_info['state']:<12} service: {service:<15} {version_info}")
    
    # Separator line at the end of each host
    print('\n' + '='*60 + '\n')