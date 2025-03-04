# Libraries
import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import subprocess
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

# Functions

def read_config(config_path="config.json"):
    """Read configuration file and return parameters."""
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            return config["window_size"], config["target"], config["known_mac_addresses"]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading configuration file: {e}")
        raise         

def resolve_mac_address(known_mac_addresses, mac_address):
    """Resolve MAC address to a name if known, otherwise return the MAC address."""
    return next((name for name, address in known_mac_addresses.items() if address == mac_address), mac_address)

def print_main_info(target, known_mac_addresses, window_size, subtitle):
    """Print the main information of the program. Subtitle will be "Training and evaluation" or "Real-time traffic analysis"."""
    print("| Wi-Fi encrypted traffic classification")
    print(f"| {subtitle}")
    print("|")
    print(f"| Target: {target} ({known_mac_addresses[target]})")
    print(f"| Window size: {window_size} seconds")

def return_csv_files(directory):
    """Return all CSV file names in the specified directory."""
    return [file for file in os.listdir(directory) if file.endswith(".csv")]

def generate_confusion_matrix(y_test, y_pred, encoder):
    """Generate and save the confusion matrix."""
    cm = confusion_matrix(y_test, y_pred)
    cm_display = ConfusionMatrixDisplay(cm, display_labels=encoder.classes_)
    cm_display.plot(cmap="Blues")   
    plt.gcf().set_size_inches(7, 7)
    plt.title("Confusion Matrix")
    plt.savefig("results/confusion_matrix.png")
    plt.show()

def filter_data(data, target_mac_address):
    """Filter data by the target MAC address."""
    data = data[(data["Transmitter"] == target_mac_address) | 
                (data["Source"] == target_mac_address) | 
                (data["Receiver"] == target_mac_address) | 
                (data["Destination"] == target_mac_address)]
    return data

def extract_features(data, target_mac_address):
    """Extract features from the data and return them."""
    avg_size = data["Length"].mean() if not data["Length"].empty else 0
    var_size = data["Length"].var() if not data["Length"].empty else -1
    max_size = data["Length"].max() if not data["Length"].empty else 0

    data = data.drop(["Length"], axis=1)

    avg_iat = data["Time"].diff(1).mean() if len(data) > 1 else 0
    var_iat = data["Time"].diff(1).var() if len(data) > 1 else -1
    
    data = data.drop(["Time"], axis=1)

    n_ul = len(data[data["Source"] == target_mac_address])
    n_dl = len(data[data["Destination"] == target_mac_address])

    return [n_ul, n_dl, avg_size, var_size, max_size, avg_iat, var_iat]

def analyze_data(window_size, target_mac_address, directory, test):
    """Analyze data by extracting features and activities for each window of the specified duration.""" 
    def split_data(data, window_size):
        """Split data into windows of the specified duration."""
        start_time = data["Time"].min()
        end_time = data["Time"].max()
        return [data[(data["Time"] >= start) & (data["Time"] < start + window_size)] 
                for start in range(int(start_time), int(end_time), window_size)]

    files = return_csv_files(directory)
    features = []
    activities = []

    for file in files:
        if not test:
            print()
        print(f"Processing file: {file}")
        if not test:
            print()
            header = ("#UL\t#DL\tAvg. Size\tVar. Size\tMax. Size\tAvg. IAT\tVar. IAT\tActivity")
            print(header if directory == "test_data" else header.replace("\tActivity", ""))

        activity = file.split("_")[0]
        data = pd.read_csv(f"{directory}/{file}", low_memory=False)    
        windows = split_data(data, window_size)

        for window in windows:
            window = filter_data(window, target_mac_address)
            window = window.drop(["No.", "Transmitter", "Receiver", "Sequence Number", "Type/Subtype"], axis=1)
            window.loc[:, "Time"] = pd.to_numeric(window["Time"])
            window.loc[:, "Length"] = pd.to_numeric(window["Length"])

            features_window = extract_features(window, target_mac_address)
            features.append(features_window)
            activities.append(activity)

            if not test:
                if directory == "test_data":
                    print(f"{features_window[0]}\t{features_window[1]}\t{features_window[2]:<8.2f}\t{features_window[3]:<8.2f}\t{features_window[4]:<8.2f}\t{features_window[5]:<8.5f}\t{features_window[6]:<8.5f}\t{activity}")
                else:
                    print(f"{features_window[0]}\t{features_window[1]}\t{features_window[2]:<8.2f}\t{features_window[3]:<8.2f}\t{features_window[4]:<8.2f}\t{features_window[5]:<8.5f}\t{features_window[6]:<8.5f}")

    return features, activities

# Note: In the folder "accuracy_vs_window_old_tests" there are some old tests that were performed, these tests can be useful for comparison.
def test_window_size(target_mac_address, test_size):
    """Test the model's accuracy across different window sizes and plot the results."""
    directory = "test_data"
    accuracies = []
    window_sizes = range(1, 121)  

    for window_size in window_sizes:
        print(f"Window size: {window_size} seconds")
        features, activities = analyze_data(window_size, target_mac_address, directory, True)
        
        encoder = LabelEncoder()
        classifier = RandomForestClassifier()
        encoded_activities = encoder.fit_transform(activities)
        X_train, X_test, y_train, y_test = train_test_split(features, encoded_activities, test_size=test_size, shuffle=True)
        classifier.fit(X_train, y_train)
        y_pred = classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        accuracies.append(float(f"{accuracy*100:.2f}"))
        print(f"Accuracy: {accuracy*100:.2f}%")

        numbers = [int(word) for word in classification_report(y_test, y_pred, target_names=encoder.classes_).split() if word.isdigit()]
        print(f"Number of tests: {numbers[-1] if numbers else "N/A"}")

    plt.plot(window_sizes, accuracies)

    coeffs = np.polyfit(window_sizes, accuracies, deg=3)  # 3rd-degree polynomial
    poly_fit = np.poly1d(coeffs)
    smooth_window_sizes = np.linspace(min(window_sizes), max(window_sizes), 500)
    plt.plot(smooth_window_sizes, poly_fit(smooth_window_sizes), "r-", label="Polynomial fit (degree 3)")

    plt.xlabel("Window size (seconds)")
    plt.ylabel("Accuracy (%)")
    plt.title("Accuracy vs Window Size")
    plt.savefig("results/accuracy_vs_window_size.png")
    plt.savefig(f"results/accuracy_vs_window_old_tests/accuracy_vs_window_{pd.Timestamp.now().strftime('%Y-%m-%d_%H-%M-%S')}.png")
    plt.show()

def main():
    # This command is used to remove the __pycache__ folder, which is created when the program is executed and not automatically removed if the program is executed with sudo
    # Since I've not found a better solution, I'm using this command to remove it manually
    if os.path.exists("__pycache__"):
        subprocess.run(["rm", "-r", "__pycache__"])
    
    window_size, target, known_mac_addresses = read_config()
    directory = "test_data"
    target_mac_address = known_mac_addresses[target]

    print_main_info(target, known_mac_addresses, window_size, "Training and evaluation")
    print()
    input("Press Enter to analyze data...")

    features, activities = analyze_data(window_size, target_mac_address, directory, False)
    
    encoder = LabelEncoder()
    classifier = RandomForestClassifier()
    encoded_activities = encoder.fit_transform(activities)
    test_size = 0.2
    X_train, X_test, y_train, y_test = train_test_split(features, encoded_activities, test_size=test_size, shuffle=True)
    classifier.fit(X_train, y_train)
    y_pred = classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print()
    print(f"Accuracy: {accuracy*100:.2f}%")     
    print(classification_report(y_test, y_pred, target_names=encoder.classes_))
    generate_confusion_matrix(y_test, y_pred, encoder)

    # Uncomment the following line to test the window size for the model and plot the accuracy vs window size graph
    
    # test_window_size(target_mac_address, test_size)
    
    return accuracy, encoder, classifier

# Main
if __name__ == "__main__":
    main()