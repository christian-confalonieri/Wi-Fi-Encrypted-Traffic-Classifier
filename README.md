<h1>Wi-Fi Encrypted Traffic Classifier</h1>

[![License: MIT][license-image]][license]

This project is an optional activity of "Wireless Internet", course of "**Computer Science and Engineering**" (MSc) held at Politecnico di Milano (2023/2024).

**Professor**: Alessandro Enrico Cesare Redondi

**Final Score**: 4 / 4

<h2>Project specification</h2>

The primary objective of this project is to design and implement a machine-learning classifier that can distinguish between different types of user activities based on Wi-Fi traffic data, without decrypting the packets. The system will be trained on a dataset collected using Wireshark and will also be able to classify "real-time" traffic data.

The following key operations will be performed:

- Traffic Sniffing: data for training and testing the classifier will be collected using Wireshark. This tool will capture packets from a Wi-Fi network, and the data will be saved in a .csv file.

    For real-time traffic analysis, the data will be collected using the pyshark library, a Python wrapper for tshark, the command-line version of Wireshark.
    
    More details about the data collection process will be provided in the next sections.

- Feature Extraction: once the traffic data is captured, we will extract various statistical features at regular intervals (every W seconds). These features will include:

    - Number of uplink and downlink packets: the number of packets sent and received by the device.
    - Packet size statistics: average, variance, and maximum packet size (minimum size is not considered since it is always 60).
    - Inter-Arrival Times: average and variance of the time intervals between packets.

    Other features, such as sequence number and packet type/subtype statistics, can also be considered. However, for this project, the above features are sufficient to achieve good classification accuracy.

- Training and Evaluation: using the extracted features, we will train a machine-learning classifier to categorize user activity. The classifier will differentiate among activities such as idle, web browsing, Spotify, and YouTube streaming.

- Performance Evaluation: the accuracy of the classifier will be assessed through a confusion matrix. This matrix will help evaluate how well the system classifies different user activities and identify any areas for improvement.

    In addition, a function, test_window_size(), will be implemented to test the classifier with different window durations and plot the results to find the best one.

- Real-time Traffic Analysis: the classifier will be used to analyze real-time traffic data. The system will continuously monitor the network and classify user activities as they occur. Data will be analyzed every W seconds, and the results will be displayed on the console.

You can find additional information about the project in the [report](report/report.pdf).

<h2>Additional Information</h2>

Remember to add captures to the [test_data](src/test_data) folder and edit the [config.json](src/config.json) file.

<h2>Copyright and license</h2>

This project is copyright 2025.

Licensed under the **[MIT License][license]**; you may not use this software except in compliance with the License.

[license]: https://github.com/christian-confalonieri/Wi-Fi-Encrypted-Traffic-Classifier/blob/main/LICENSE
[license-image]: https://img.shields.io/badge/License-MIT-blue.svg