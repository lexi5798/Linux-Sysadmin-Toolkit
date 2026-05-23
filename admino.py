#!/usr/bin/env python3
#Import modules

import argparse # Module to parse command line arguments
import subprocess # Module for running external commands
import socket # Module for work with hostnames
import re # Module for regular expressions
from collections import defaultdict # Module to organize data
import os # Module for interacting with os

# Define functionss

# Function to get get_hostname_info
def get_hostname_info():
    try:
        # Retrieve current system hostname using socket and assign it to hostname variable
        hostname = socket.gethostname()

        # Print the hostname info
        print(f"Hostname: {hostname}")

        return hostname
    # Error meessage if there is an error during hostnae retrieval
    except Exception as e:
        print(f"Error retrieving hostname: {e}")
        return None

# Function to get IP address for a specific interface
def get_ip(interface):
    try:
        # Retrieve network interface information and assign it to result variable
        result = subprocess.check_output(['ip', 'addr', 'show', interface])
        decoded_result = result.decode('utf-8')

        # Split the decoded result to extract the IP
        ip_address = decoded_result.split('inet ')[1].split('/')[0]

        # Print the IP address with the specified interface
        print(f"IP address for '{interface}': {ip_address}")

        return ip_address
    # Error meesage if an error occurs during IP address retrieval
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving IP for {interface}: {e}")
        return None


# Function to get a list of users for a specific group
def get_group_users(group):
    try:
        # Use getent command to retrieve group information and extract the list of users
        result = subprocess.check_output(['getent', 'group', group])
        # Convert bytes to string and split, extrating the list of users from the fourth field of results
        users = [str(user) for user in result.decode('utf-8').split(':')[3].split(',')]

        # Print the list of group users
        print(f"List of users in '{group}':")
        print("\n".join(users))

        return users
    # Error message if an error occurs during user information retrieval
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving user information: {e}")
        return None

# Function to get a list of users on the system
def get_users():
    try:
        # Use cut to extract username from etc/passwd file
        result = subprocess.check_output(['cut', '-d', ':', '-f', '1', '/etc/passwd'])
        # Convert bytes to strng and split lines, removing the last empty string
        users = [str(user) for user in result.decode('utf-8').split('\n')[:-1]]

        # Print the list of users
        print("List of users on the system:")
        print("\n".join(users))

        return users
    # Error message if an error occurs during user information retrieval
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving user information: {e}")
        return None

# Funcion to get directory tree
def get_tree(user):
    try:
        # Path to user's directory
        home_dir = "/home/{}".format(user)
        # Use tree command to obtain the directory tree of specified home directory
        result = subprocess.check_output(['tree', home_dir], universal_newlines=True)
        return result
    # Error message if an eror occurs during direcotry tree retrieval
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving directory tree for {user}: {e}")
        return None

#Function to get list of IPs from last remote connections
def get_last_connections():
    try:
        # Use last command and -i option to retrieve logins, set universal_newlines=True to reutn as string
        result = subprocess.check_output(['last', '-i'], universal_newlines=True)
        # Extract IP address using regular expression
        ip_addresses = re.findall(r'\d+\.\d+\.\d+\.\d+', result)
        print("List of IP addresses from last remote connections:")
        print("\n".join(ip_addresses))

        return ip_addresses
    # Error message if an error occurs during IP retrieval from last connections
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving IP's of last connections: {e}")
        return None

# Function to get top 10 processes which are use more %memory
def get_top_processes():
    try:
        # Execute the ps aux command to obtain information about all processes
        ps_process = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)

        # Read the output of the ps aux command
        ps_output, _ = ps_process.communicate()

        # Decode the output from bytes to string
        ps_output = ps_output.decode('utf-8')

        # Split the output into lines
        ps_lines = ps_output.split('\n')

        # Extract the header and process lines
        header = ps_lines[0]
        processes = ps_lines[1:]

        # Print the header
        print(header)

        # Print the top 10 processes
        for process in processes[:10]:
            print(process)
    # Error message if an error occurs during the retrieval of top processes
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving top processes: {e}")
        return None

# Function to get sudo commands
def get_sudo_commands():
    try:
        # Read the contents of the auth.log file
        with open('/var/log/auth.log', 'r') as log_file:
            log_content = log_file.read()

        # Define regular expression patterns
        timestamp_pattern = re.compile(r'^\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}')
        sudo_pattern = re.compile(r'sudo:\s+(.+)$')

        # Find all sudo entries in the log content
        sudo_entries = []

        for line in log_content.split('\n'):
            if 'sudo:' in line:
                timestamp_match = timestamp_pattern.match(line)
                sudo_match = sudo_pattern.search(line)
                if timestamp_match and sudo_match:
                    timestamp = timestamp_match.group()
                    command = sudo_match.group(1)
                    sudo_entries.append((timestamp, command))

        # Display organized sudo commands
        for timestamp, command in sudo_entries:
            print(f"\nTimestamp: {timestamp}")
            print(f"Command: {command}")

    # Error message if an error occurs during the retrieval of sudo commands
    except Exception as e:
        print(f"Error retrieving sudo commands: {e}")

#Distinctive function: Authenication Events.
#This function will analyze authentication logs to provide insights into user login activity, including successful and failed login attempts.
def distinctive_function():
    # Retrieve authentication events from system logs
    try:
        result = subprocess.check_output(['cat', '/var/log/auth.log'], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving authentication events: {e}")
        return

    # Define regular expressions for successful and failed SSH logins
    successful_login_pattern = re.compile(r'sshd.*Accepted.*')
    failed_login_pattern = re.compile(r'sshd.*Failed.*')

    # Extract and process the authentication events
    events = result.split('\n')
    successful_logins = []
    failed_logins = []

    # Go through each event in events list
    for event in events:
        # Check if event matches pattern for succesful logins and if so, add to list of succesful logins
        if successful_login_pattern.search(event):
            successful_logins.append(event)
        # Check if the event matches the pattern for failed SSH logins and if so, add to failed list
        elif failed_login_pattern.search(event):
            failed_logins.append(event)

    # Display results
    print("Successful Logins:")
    for login in successful_logins:
        print(login)

    print("\nFailed Logins:")
    for login in failed_logins:
        print(login)

def main():
    #Custom message with line break
    description = "Admino system information script.\nPlease follow the instructions below to use it"

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    # Define command-line arguments
    parser.add_argument("-H", help="Provides hostname information.", action="store_true")
    parser.add_argument("-i", help="Provides the IP address of provided <interface>.")
    parser.add_argument("-u", help="Provides list of users of the system.", action="store_true")
    parser.add_argument("-g", help="Provides the list of users for a specific <group>.")
    parser.add_argument("-t", help="Provides the directory list tree for a system <user>.")
    parser.add_argument("-l", help="Provides the list of IPs from  last remote connections.", action="store_true")
    parser.add_argument('-p', help="Provides the top 10 processes from which are using more memory", action="store_true")
    parser.add_argument("-s", help="Provides the list of SUDO invoked commands from auth.log", action="store_true")
    parser.add_argument("-d", help="Provides information about user authentication events.", action="store_true")

    # Parse comand-line arguments
    args = parser.parse_args()

    # If no arguments are provided, print the help message
    if not any(vars(args).values()):
        parser.print_help()

    # Call the appropriate function based on the provided arguments
    if args.H:
        get_hostname_info()
    if args.i:
        get_ip(args.i)
    if args.u:
        get_users()
    if args.g:
        get_group_users(args.g)
    if args.t:
        print(get_tree(args.t))
    if args.l:
        get_last_connections()
    if args.p:
        get_top_processes()
    if args.s:
        get_sudo_commands()
    if args.d:
        distinctive_function()

if __name__ == "__main__":
    main()

