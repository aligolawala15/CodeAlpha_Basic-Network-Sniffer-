import csv

from scapy.all import sniff, IP, TCP, UDP, ICMP


# ======================================
# Packet Counter
# ======================================

packet_count = 0


# ======================================
# Protocol Statistics
# ======================================

protocol_count = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}


# ======================================
# Create CSV File
# ======================================

csv_file = open(
    "packets.csv",
    "w",
    newline="",
    encoding="utf-8"
)

writer = csv.writer(csv_file)

writer.writerow([
    "Packet Number",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Size"
])


# ======================================
# Packet Handler
# ======================================

def packet_handler(packet):

    global packet_count

    packet_count += 1

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = "Other"
        source_port = ""
        destination_port = ""

        print("\n--------------------------------")
        print("Packet Captured")
        print("--------------------------------")

        print(f"Packet Number  : {packet_count}")
        print(f"Packet Size    : {len(packet)} bytes")
        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")

        # TCP
        if TCP in packet:

            protocol = "TCP"
            protocol_count["TCP"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print("Protocol       : TCP")
            print(f"Source Port    : {source_port}")
            print(f"Destination Port: {destination_port}")

        # UDP
        elif UDP in packet:

            protocol = "UDP"
            protocol_count["UDP"] += 1

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print("Protocol       : UDP")
            print(f"Source Port    : {source_port}")
            print(f"Destination Port: {destination_port}")

        # ICMP
        elif ICMP in packet:

            protocol = "ICMP"
            protocol_count["ICMP"] += 1

            print("Protocol       : ICMP")

        # Other
        else:

            protocol = "Other"
            protocol_count["Other"] += 1

            print("Protocol       : Other")

        # Payload
        if packet.payload:
            print(f"Payload        : {bytes(packet.payload)[:50]}")
        else:
            print("Payload        : None")

        # ======================================
        # Save to CSV
        # ======================================

        writer.writerow([
            packet_count,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            len(packet)
        ])

        csv_file.flush()


# ======================================
# Start Program
# ======================================

print("======================================")
print("       BASIC NETWORK SNIFFER")
print("======================================")

# Ask user how many packets to capture
count = int(input("Enter number of packets to capture: "))

print("\nCapturing packets...")
print("Press CTRL+C to stop early.\n")


try:

    sniff(
        count=count,
        prn=packet_handler,
        store=False
    )

except KeyboardInterrupt:

    print("\nSniffer stopped by user.")


# ======================================
# Protocol Statistics
# ======================================

print("\n======================================")
print("       SNIFFER FINISHED")
print("======================================")

print("\nProtocol Statistics")
print("-------------------")

for protocol, count in protocol_count.items():
    print(f"{protocol}: {count}")

print(f"\nTotal Packets: {packet_count}")


# ======================================
# Close CSV
# ======================================

csv_file.close()

print("\nCSV file saved as: packets.csv")