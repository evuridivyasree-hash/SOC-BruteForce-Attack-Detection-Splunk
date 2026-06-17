# SOC Analyst Lab: Brute Force Attack Detection using Splunk

![Image](https://github.com/user-attachments/assets/fdb41188-bd7d-4af3-9762-53f64ee05cf3)

![Image](https://github.com/user-attachments/assets/88e3804b-3213-4094-baf6-d215595f6280)

![Image](https://github.com/user-attachments/assets/fadfc3a9-0b19-4f89-ac7b-c292b9b9b274)

![Image](https://github.com/user-attachments/assets/57aa9ff0-12f3-4989-9eee-8c9144add660)

![Image](https://github.com/user-attachments/assets/9420313b-d5ba-471c-9a72-e2e1236f02de)

![Image](https://github.com/user-attachments/assets/8e2d19e0-39d2-4f83-aa1e-89816ab6255a)

![Image](https://github.com/user-attachments/assets/7c3ccbfe-3510-40ec-bd28-bdeaf63b417b)

## Objective
The objective of this lab is to simulate and detect a brute force attack using Splunk SIEM by analyzing authentication logs.

## Tools Used
- Splunk Enterprise
- Linux Authentication Logs
- Virtual Lab Environment

## Attack Description
A brute force attack occurs when an attacker repeatedly attempts to guess login credentials until successful access is obtained.

## Attack Simulation
Multiple failed SSH login attempts were generated against the system.

Example log events:

Failed password for user admin from 192.168.1.10 port 22
Failed password for user admin from 192.168.1.10 port 22
Successful login for user admin from 192.168.1.10 port 22

## Splunk Detection Query

index=main ("Failed password" OR "Successful login")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip

## Analysis
The logs show multiple failed authentication attempts from the same source IP address, indicating a brute force attack.

Attacker IP: 192.168.1.10

## Detection Outcome
Using Splunk SIEM, we were able to identify suspicious authentication activity and detect the brute force attack.
