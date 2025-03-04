# Libraries
import training_and_evaluation
import subprocess
import pyshark
import time
import csv 
import os
import numpy as np

# Functions

def list_interfaces():
    """List available network interfaces and return a mapping."""
    interface_mapping = {}
    result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
    interfaces = result.stdout.split("\n")[:-1]

    print()
    for i, interface in enumerate(interfaces, start=1):
        interface_mapping[i] = interface.split(". ")[1]
        print(f"{i}. {interface_mapping[i]}")
    return interface_mapping

def choose_interface(interface_mapping):
    """Prompt user to choose an interface from the available list."""
    interface = -1
    while interface not in interface_mapping.keys():
        try:
            interface = int(input("\nChoose an interface: "))
        except:
            pass
    return interface_mapping[interface]

def check_monitor_mode(interface):
    """Check if the specified interface is in monitor mode."""
    result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True)
    return "monitor" in result.stdout

def print_main_info(target, known_mac_addresses, window_size, subtitle, accuracy):
    """Print main information including target, window size, subtitle, and accuracy."""
    print()
    training_and_evaluation.print_main_info(target, known_mac_addresses, window_size, subtitle)
    print("|")
    print(f"| Accuracy: {accuracy*100:.2f}% ")
    

def print_interface_info(interface, mode):
    """Print the interface chosen with its type (Monitor/Managed)."""
    print()
    print(f"| Interface: {interface}")
    print(f"| Type: {"Monitor" if mode else "Managed"}")
    print()

def handle_wlan_frame(type_subtype):
    """Convert WLAN frame type/subtype from hex to the same format as Wireshark."""
    wlan_frame_types = {
        "0x0000": "Association Request", 
        "0x0001": "Association Response", 
        "0x0002": "Reassociation Request", 
        "0x0003": "Reassociation Response", 
        "0x0004": "Probe Request", 
        "0x0005": "Probe Response", 
        "0x0006": "Measurement Pilot", 
        "0x0008": "Beacon frame", 
        "0x0009": "ATIM", 
        "0x000a": "Disassociate", 
        "0x000b": "Authentication", 
        "0x000c": "Deauthentication", 
        "0x000d": "Action", 
        "0x000e": "Action No Ack", 
        "0x000f": "Aruba Management", 
        "0x0012": "Trigger", 
        "0x0013": "TWT Ack", 
        "0x0014": "Beamforming Report Pull", 
        "0x0015": "VHT/HE/EHT/RANGING NDP Announcement", 
        "0x0017": "Control Wrapper", 
        "0x0018": "802.11 Block Ack Req", 
        "0x0019": "802.11 Block Ack", 
        "0x001a": "Power-Save poll", 
        "0x001b": "Request-to-send", 
        "0x001c": "Clear-to-send", 
        "0x001d": "Acknowledgement", 
        "0x001e": "CF-End (Control Frame)", 
        "0x001f": "CF-End + CF-Ack (Control Frame)", 
        "0x0020": "Data", 
        "0x0021": "Data + CF-Ack", 
        "0x0022": "Data + CF-Poll", 
        "0x0023": "Data + CF-Ack + CF-Poll", 
        "0x0024": "Null function (No data)", 
        "0x0025": "Acknowledgement (No data)", 
        "0x0026": "CF-Poll (No Data)", 
        "0x0027": "CF-Ack/Poll (No data)", 
        "0x0028": "QoS Data", 
        "0x0029": "QoS Data + CF-Acknowledgement", 
        "0x002a": "QoS Data + CF-Poll", 
        "0x002b": "QoS Data + CF-Ack + CF-Poll", 
        "0x002c": "QoS Null function (No data)", 
        "0x002e": "QoS CF-Poll (No data)", 
        "0x002f": "QoS CF-Ack + CF-Poll (No data)", 
        "0x0030": "DMG Beacon", 
        "0x0031": "S1G Beacon", 
        "0x0162": "Poll", 
        "0x0163": "Service Period Request", 
        "0x0164": "Grant", 
        "0x0165": "DMG Clear-to-send", 
        "0x0166": "DMG Denial-to-send", 
        "0x0167": "Grant Acknowledgement", 
        "0x0168": "Sector Sweep", 
        "0x0169": "Sector Sweep Feedback", 
        "0x016a": "Sector Sweep Acknowledgement"
    }
    return wlan_frame_types.get(type_subtype, "Unknown type/subtype")

def hex_to_ascii(hex_string):
    """Convert hex string to ASCII string."""
    hex_string = hex_string.replace(":", "")
    if hex_string != "SSID <MISSING>":
        bytes_data = bytes.fromhex(hex_string)
        ascii_string = bytes_data.decode("ascii")
        return ascii_string
    else: 
        return ""

def save_to_csv(data, directory, filename):
    """Save data to a CSV file."""
    os.makedirs(directory, exist_ok=True)
    with open (f"{directory}/{filename}", "w", newline="") as csvfile:
        fieldnames = ["No.", "Time", "Transmitter", "Source", "Receiver", "Destination", "Length", "Sequence Number", "Type/Subtype"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_STRINGS)
        writer.writeheader()
        writer.writerows(data)
    
    print(f"Data saved in {directory}/{filename}")

def guess_activity(features, encoder, classifier):
    """Predict the activity based on features using the trained model."""
    return encoder.inverse_transform(classifier.predict(features))[0]

def capture_traffic(interface, target, known_mac_addresses, window_size, encoder, classifier):
    """Capture traffic on the specified interface and classify the activity."""
    try:
        input("Press Enter to start capturing traffic.\nNote: displayed traffic is filtered by target to ensure readability.")
    except KeyboardInterrupt:
        exit(1)

    capture = pyshark.LiveCapture(interface=interface)
    start_time = time.time()
    data = []   
    packet_count = 1
    
    print()
    print("No.\tTime\t\tTransmitter\t\tSource\t\t\tReceiver\t\tDestination\t\tLength\t\tSequence Number\t\tType/Subtype")
    
    try:
        for packet in capture.sniff_continuously(): 
            elapsed_time = time.time() - start_time
            if elapsed_time > window_size:
                break
            
            packet_info = {
                "No.": str(packet_count), 
                "Time": f"{elapsed_time:.9f}", 
                "Transmitter": getattr(packet.wlan, "ta", "") if "wlan" in packet else "",
                "Source": getattr(packet.wlan, "sa", "")  if "wlan" in packet else "", 
                "Receiver": getattr(packet.wlan, "ra", "") if "wlan" in packet else "",
                "Destination": getattr(packet.wlan, "da", "") if "wlan" in packet else "", 
                "Length": getattr(packet, "length", ""), 
                "Sequence Number": getattr(packet.wlan, "seq", "") if "wlan" in packet else "", 
                "Type/Subtype": handle_wlan_frame(getattr(packet.wlan, "fc_type_subtype", "")) if "wlan" in packet else ""
            }

            if packet_info["Transmitter"] == known_mac_addresses[target] or packet_info["Source"] == known_mac_addresses[target] or packet_info["Receiver"] == known_mac_addresses[target] or packet_info["Destination"] == known_mac_addresses[target]:
                print(f"{packet_info["No."]}\t{packet_info["Time"]}\t{training_and_evaluation.resolve_mac_address(known_mac_addresses, packet_info["Transmitter"]):<17}\t{training_and_evaluation.resolve_mac_address(known_mac_addresses, packet_info["Source"]):<17}\t{training_and_evaluation.resolve_mac_address(known_mac_addresses, packet_info["Receiver"]):<17}\t{training_and_evaluation.resolve_mac_address(known_mac_addresses, packet_info["Destination"]):<17}\t{packet_info["Length"]:<8}\t{packet_info["Sequence Number"]:<16}\t{packet_info["Type/Subtype"]:<35}")
            
            data.append(packet_info)
            packet_count += 1

    except KeyboardInterrupt:
        capture.close()
        print("\nCapturing stopped.")
        exit(1)

    capture.close()
    print("\nCapturing completed.")

    directory = "real_time_traffic_data"
    save_to_csv(data, directory, "last_capture.csv")
    features, _ = training_and_evaluation.analyze_data(window_size, known_mac_addresses[target], directory, False)
    subprocess.run(["rm", "-r", directory])
    
    activity = guess_activity(features, encoder, classifier)
    print(f"\nTime elapsed: {elapsed_time}")
    print(f"Activity: {activity}")
    print()
    return activity

def extract_unique_activities(directory):
    """Extract unique activities from the CSV files in the directory."""
    activities = [file.split("_")[0] for file in training_and_evaluation.return_csv_files(directory)]
    return np.unique(activities)

def main():
    accuracy, encoder, classifier = training_and_evaluation.main()
    window_size, target, known_mac_addresses = training_and_evaluation.read_config()

    print_main_info(target, known_mac_addresses, window_size, "Real-Time Traffic Analysis", accuracy)
    interface = choose_interface(list_interfaces())
    mode = check_monitor_mode(interface)
    print_interface_info(interface, mode)

    if not mode:
        print("Please enable monitor mode and try again.")
        exit(1)
    
    unique_activities = extract_unique_activities("test_data")
    activities_guessed = []

    while True:
        activity_guessed = capture_traffic(interface, target, known_mac_addresses, window_size, encoder, classifier)   
        activities_guessed.append(activity_guessed)
        last_ten = activities_guessed[-10:]
        occurrences = [(activity, last_ten.count(activity) / len(last_ten) * 100) for activity in set(unique_activities)]

        print(f"Last 10 guesses: {last_ten}")
        print(f"Percentage occurrence of the last 10 guesses: {occurrences}")
        print()

# Main
if __name__ == "__main__":
    main()