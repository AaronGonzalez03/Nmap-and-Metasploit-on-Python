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
def scan_arguments(port_range, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity):
    args = f"{port_range} {scan_velocity} {os_detection} {victims_machine_state} {ports_state} {verbosity}"
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
            if start >= 1 and end <= 65535:
                port_range = f'-p {start}-{end}'
                break
            else:
                print("Invalid range. Ports must be between 1 and 65535, and start <= end.")
        except ValueError:
            print("Invalid format. Use 'start-end' (example: 1-1000) or 'ALL'.")


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
        os_detection = None
        break
    else:
        print("Invalid input. Please enter 'yes' or 'no'.")


# Victim's machine state option
while True:
    victims_machine_state = input("Do you want to know if the machine is up or down? (yes/no): ").strip().lower()
    if victims_machine_state == 'yes':
        pass # Nmap by default checks if the host is up by doing ping
    elif victims_machine_state == 'no':
        victims_machine_state = '-Pn'
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
        ports_state = None
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
        print("invalid input. Pls enter low, medium or high.")



print(f"Final scan arguments: {f"IP to scan: {ip_address}", f"Scan arguments: {scan_arguments(port_range, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity)}"}")
# Show to the user the final nmap command that will be executed
print(f"Final scan command: nmap {scan_arguments(port_range, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity)} {ip_address}")


continue_scan = input("Do you want to proceed with the scan? (yes/no): ").strip().lower()
if continue_scan != 'yes':
    print("Scan aborted by user.")
    print("Exited the program.")
    exit()
elif continue_scan == 'yes':
    print(f"Starting the scan on {ip_address}...")
# Execute the scan and save the results
results = scanner.scan(ip_address, arguments=scan_arguments(port_range, scan_velocity, os_detection, victims_machine_state, ports_state, verbosity))
#SHOW RESULTS OF THE SCAN
print(results)