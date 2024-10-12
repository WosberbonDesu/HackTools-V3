# HackTools-V3
# Email Bomber & Network Tools

This is a Python-based project that includes multiple functionalities such as an email bomber, a network scanner, and a network sniffer. The project also includes tools for listing devices on the network and blocking internet access for specific devices using ARP spoofing.

## Features

- **Email Bomber**: Send multiple emails to a target email address with customizable bomb modes.
- **NetScanner**: Scan the local network for connected devices based on an IP range.
- **Network Sniffer**: Monitor network traffic and capture DNS responses and HTTP requests.
- **List Devices & Block**: List all devices on the network and block their internet access using ARP spoofing.

How to Use
This project contains four main functionalities. Each one can be accessed through the GUI.

1. Email Bomber
The Email Bomber sends multiple emails to a specified target with customizable modes.

Open the application and click the Email Bomber button.
Enter the target email, bomb mode, email server, and your email credentials.
Press Start Bombing to begin the email bombing process.
Important: Use this feature responsibly and for testing purposes only.

2. Network Scanner
The Network Scanner scans a specified IP range and lists all devices found on the network.

Click the NetScanner button.
Enter the IP range in CIDR notation (e.g., 192.168.1.0/24).
Press Start Scanning to list all devices on the network.
3. Network Sniffer
The Network Sniffer captures network traffic and displays DNS and HTTP requests.

Click the Network Sniffer button.
Select the network interface from the dropdown menu.
Press Start Sniffing to capture network traffic.
Press Stop Sniffing to end the traffic capture.
4. List Devices & Block Internet
The List Devices & Block feature allows you to scan the network, list devices, and block their internet access using ARP spoofing.

Click the List Devices and Block button.
The app will automatically detect your local IP and gateway IP.
Enter the IP range (e.g., 192.168.214.0/24).
Press Scan Network to list all devices on the network.
Select a device from the list and press Block Internet to block its internet connection.
Project Structure
Here's a breakdown of the key files and their purposes:

main.py: The entry point of the project.
EmailBomberGUI: The main class responsible for the GUI and handling user interactions.
Email_Bomber: A separate class handling the logic for sending emails.
scapy and requests are used extensively to handle network traffic and identify devices.
Example Screenshot

The image shows the graphical interface with detected local IP and gateway IP.

Contributing
Fork the repository.
Create your feature branch (git checkout -b feature/YourFeature).
Commit your changes (git commit -m 'Add Some Feature').
Push to the branch (git push origin feature/YourFeature).
Open a pull request.
Usage Disclaimer
This project is created for educational purposes only. Please do not use it for malicious or illegal activities. Misuse of this software is solely the responsibility of the user.

