#!/bin/bash

TARGET_IP="127.0.0.1"  # Change to your target's IP

# SYN scan (stealthy)
nmap -sS -T4 -p 1-100 --scan-delay 500ms $TARGET_IP

# TCP connect scan (more visible)
# nmap -sT -p 500-600 --scan-delay 100ms $TARGET_IP
