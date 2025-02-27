# Flow Analysis from PCAP File

This project provides a Python script for analyzing network traffic captured in a PCAP file. The script reads the PCAP file, extracts relevant information about network flows, and prints the results, such as the number of packets, bytes sent/received, and timestamps. This project uses the dpkt library to parse and analyze the packet data.
Requirements

Before running the script, ensure you have the required Python libraries installed. You can install them using the following:

pip install dpkt

Usage

    Prepare the PCAP File: Place your PCAP file in the same directory as the script or provide the path to the file.
    Run the Script: Execute the script in your terminal or IDE. If the script and the PCAP file are in the same directory, simply run:

python flow_analysis.py

If the script and PCAP file are in different directories, make sure to provide the correct path to the PCAP file in the code.
How It Works

    The script reads the provided PCAP file and processes each packet.
    It extracts information such as the source and destination IP addresses, source and destination ports, protocol type (TCP/UDP), and the payload length.
    For each flow (a pair of source-destination IP and port with a protocol), the script keeps track of the following:
        Number of packets sent and received.
        Number of bytes sent and received.
        Timestamp of the first and last packet in the flow.
    The flows are stored in a dictionary, and the results are printed to the console.

Example Output

The output will display the flow information for each identified flow:

### flow number 1
192.168.0.1 , 192.168.0.2 --> 80 , 443 : 500 ; sent packets: 3 , received packets: 2 , sent bytes: 400 , received bytes: 200 , timestamp: (2025-02-01 12:30:00, 2025-02-01 12:35:00)

Functions
print_flows(dic)

This function is responsible for printing the flow information stored in the dic dictionary. It outputs the flow number, source and destination IP addresses, ports, protocol, packet counts, byte counts, and timestamps.
find_flows(pcap)

This function processes each packet in the PCAP file:

    It extracts the necessary packet information, including IP addresses, ports, and protocols.
    It tracks and updates flow information in the dic dictionary.
    It calls the print_flows() function to display the results.
