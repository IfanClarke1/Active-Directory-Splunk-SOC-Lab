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


