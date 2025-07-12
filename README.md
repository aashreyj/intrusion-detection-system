<H1 style="text-align: center;"> CS5.470: Systems and Network Security </H1>
<H3 style="text-align: center;"> Network-based Intrusion Detection System </H3>

## Description

This project is an implementation of a Network-based Intrusion Detection System in Python. The user-interface is a menu-driven function that performs the following actions based on the user input:

1. **Start / Stop IDS:** Toggles the IDS thread to start or stop running based on the current state. When the IDS thread is started for the first time, the `ids.log` file is created to store the logging details.
2. **View Life Traffic:** Creates a new thread to show the user live captured packets from the default network interface.
3. **View Intrusion Logs:** Summarizes the contents of the `ids.log` file in a tabular manner to show various attack details in the mentioned format.
4. **Display Blocked IPs:** Shows a list of IPs that have been blocked using IPtables
5. **Clear Blocked IP list:** Clear the blacklisted IPs by unblocking them from IPtables firewall
6. **Unblock an IP:** Unblock a single IP address by deleting the IPtables rule
7. **Exit:** Stop running threads gracefully and exit the program

## How To Build

1. The following steps assume that the user has superuser (`sudo`) privileges on the machine and that a Python3 virtual environment has already been created where the script is intended to run. If not, please create and activate a new virtual environment using the following commands:

    ```
    python3 -m venv .venv
    source .venv/bin/activate
    ```

2. Install the required dependencies using the `requirements.txt` file by running the following command:

    ```
    pip3 install -r requirements.txt
    ```

3. Start the main thread using the following command:

    ```
    sudo $(which python3) main.py
    ```

4. To exit, please enter 7 on the menu screen.

## Explanation of the source code files

The assignment consists of the following files, each of which serves a single responsibility in the Intrusion Detection System. The following source code files have been submitted:

1. **main.py:** This is the entry point of the program and is responsible for handling the user input and triggering corresponding actions based on the user's choice.

    It defines how the user input will be handled and how the logs will be aggregated and shown to the user from the `ids.log` file. It also defines the signal handlers for `SIGINT` and `SIGTSTP` that have special uses in the implementation. The signal handler for `SIGINT` ensures that the user exits the program using the menu option so that all resources can be cleaned up and the termination is graceful.

2. **ids_service.py:** This file contains the core implementation of the Intrusion-Detection service and is responsible for the actions of the IDS thread, when it is running.

    It monitors network packets to detect two types of attacks—TCP port scanning and OS fingerprinting—based on specific thresholds and patterns like port range and TCP flags. When suspicious behavior is detected, it logs the event asynchronously and blocks the offending IP using `iptables`. The script maintains two separate `pandas DataFrames` to track recent packet data for both attack types and uses time-based windows to clean up old entries.

3. **iptables_handler.py:** This file contains the functions that are used to interact with the system-wise `IPtables` firewall service to block/unblock IP addresses, as desired by the user and the IDS thread. Each operation runs in a separate thread to ensure minimal blocking of the main IDS thread.

4. **utils.py:** This is the utilities file and contains methods and constants that are used throughout the project. The constants include the choices that the user can make along with mutex locks that need to be aquired before printing to `STDOUT` or performing an IP address blocking/unblocking operation.

5. **view_traffic.py:** Finally, this file contains the function that will be called when the user chooses to view the live traffic. This is a blocking thread and the user will not be able to perform any other operation while this thread is running.

## Key Highlights of the Implementation

1. The IDS runs as a Python Thread, allowing it to operate independently and be managed cleanly (start/stop) within a larger application. The `assignment3.py` constitutes this larger application and manages the user interface and input/output handling.

2. It maintains rolling DataFrames for each attack type with timestamp-based filtering to keep only recent entries, enabling fast analysis.

3. The IDS supports safe shutdown via a `threading.Event`, and uses `threading.Lock` for shared state like the blocked IP set.

4. The `utils.py` file implements `thread_safe_print` and uses `threading.Lock` to ensure thread-safe access and operations on shared resources like the console and the `BLOCKED_IP_SET`. It also declares global variables for IDS control such as `IDS_THREAD`, `VIEW_TRAFFIC_THREAD`, and `FIREWALL_UPDATE_THREAD`, which assist in managing various threads and configurations of the IDS system.

5. Each intrusion is logged in a detailed, structured manner (including port/flag info, timestamps, etc.) to aid future analysis.

6. We have used the `iptc` library to dynamically insert `drop rules` into `iptables` when **malicious activity is detected,** effectively blocking attackers in real-time.
