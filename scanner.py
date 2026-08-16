import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    try:
        if sock.connect_ex((ip, port)) == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            return port, service

    except socket.error:
        pass

    finally:
        sock.close()

    return None


def scan_target(target, start_port, end_port):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Invalid target.")
        return

    print("\n" + "=" * 55)
    print("              NETWORK PORT SCANNER")
    print("=" * 55)
    print(f"Target      : {target}")
    print(f"IP Address  : {ip}")
    print(f"Port Range  : {start_port}-{end_port}")
    print("=" * 55)

    print(f"[*] Scanning ports {start_port}-{end_port}...\n")

    start_time = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(
            lambda port: scan_port(ip, port),
            range(start_port, end_port + 1)
        )

        for result in results:
            if result:
                port, service = result
                open_ports.append((port, service))
                print(f"[+] OPEN   {port:<6} {service}")

    elapsed = time.time() - start_time

    print("\n" + "-" * 55)

    if open_ports:
        print(f"[+] Open ports found: {len(open_ports)}")
    else:
        print("[-] No open ports found.")

    print(f"[*] Scan completed in {elapsed:.2f} seconds")
    print("-" * 55)


def main():
    if len(sys.argv) == 4:
        target = sys.argv[1]

        try:
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
        except ValueError:
            print("[-] Ports must be numbers.")
            return

    else:
        print("\nNetwork Port Scanner")
        print("-" * 30)

        target = input("Enter target IP or domain: ")

        try:
            start_port = int(input("Start port: "))
            end_port = int(input("End port: "))
        except ValueError:
            print("[-] Ports must be numbers.")
            return

    if not (1 <= start_port <= 65535):
        print("[-] Invalid start port.")
        return

    if not (1 <= end_port <= 65535):
        print("[-] Invalid end port.")
        return

    if start_port > end_port:
        print("[-] Start port must be <= end port.")
        return

    scan_target(target, start_port, end_port)


if __name__ == "__main__":
    main()
