#!/bin/bash

# Test OS Fingerprinting Detection
# Simulates various TCP flag combinations that should trigger your IDS

TARGET_IP="127.0.0.1"  # Change to your machine's IP if testing remotely
TARGET_PORT="80"        # Commonly probed port
DELAY="0.5"             # Seconds between packets

# Define flag combinations (matches your VALID_FLAGS)
FLAGS=(
    "SYN"       # 0x02
    "ACK"       # 0x10
    "FIN"       # 0x01
    "SYN,ACK"   # 0x12
    "FIN,ACK"   # 0x11
    "SYN,FIN"   # 0x03
    "SYN,ACK,FIN" # 0x13
)

echo "[+] Starting OS fingerprinting test against $TARGET_IP:$TARGET_PORT"
echo "[+] Sending packets with these flag combinations: ${FLAGS[@]}"
echo "[!] Your IDS should detect this as OS fingerprinting after 5+ unique flag combinations"

# Send packets with different flags
for flags in "${FLAGS[@]}"; do
    echo "[+] Sending packet with flags: $flags"
    
    # Using hping3 for precise flag control
    case "$flags" in
        "SYN") hping3 -S -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "ACK") hping3 -A -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "FIN") hping3 -F -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "SYN,ACK") hping3 -S -A -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "FIN,ACK") hping3 -F -A -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "SYN,FIN") hping3 -S -F -c 1 -p $TARGET_PORT $TARGET_IP ;;
        "SYN,ACK,FIN") hping3 -S -A -F -c 1 -p $TARGET_PORT $TARGET_IP ;;
    esac

    sleep $DELAY
done

echo "[+] Test complete. Check your IDS logs for OS fingerprinting detection"
