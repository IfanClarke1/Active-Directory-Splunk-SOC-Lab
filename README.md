# Active-Directory-Splunk-SOC-Lab
A simulated SOC environment using Active DIrectory, Splunk SIEM, Windows Server, Ubuntu, and Kali Linux to investigate security incidents

## Overview

This project is a simulated enterprise Active Directory environment designed to demonstrate SOC monitoring, Windows security event monitoring, threat detection and incident investigation.

The lap replicates a small corporate network where a Windows Server 2022 Domain Controller provides identity and access management, while Splunk acts as the SIEM. I am running Splunk Universal Forwarder to send Windows logs to my Splunk instance in Ubuntu

## Lab Architecture

**Windows Server 2022**
* Active Directory Domain Controller
* DNS Server
* User and Group Management
* Security Event Generation
* Splunk Universal Forwarder

**Ubuntu**
* Splunk Enterprise SIEM
* Log Ingestion and Analysis
* Detection rules and dashboards

**Kali Linux**
* Attack simulation 

## Objectives

The project aims to simulate common security scenarios such as:

* Brute force attacks
* password spraying
* Privileged account changes
* suspicious authentication activity
* PowerShell abuse
* Account manipulation

## Detection Engineering

I created the following alerts in Splunk:

* Failed Login (index=* EventCode=4625)

* Successful Login (index=* EventCode=4624)

* User Account Created (index=* EventCode=4720)

* User Added to Privileged Group (index=* EventCode=4728)

I then activated all my new alerts as a test:

<img width="725" height="360" alt="image" src="https://github.com/user-attachments/assets/eb5fb9ac-f042-4b8e-b9e3-435b94246571" />

## Incidents

From there I planned out the incidents I wanted to simulate and respond to. The ones I came up with were as follows:

* Multiple Failed Logins
* New User Created
* Privileged Group Change
* Encoded Powershell
* PowerShell Network Connections

### Incident 001 - Multiple Failed Logins







