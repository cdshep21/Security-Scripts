#!/bin/bash
 
######################################################################################################################
# Nessus Agent Installation Script (RHEL / Oracle Linux)
# Author: Corderius Shepherd
# Version: 1.16
# Last Updated: 11-APR-2025
#
# DESCRIPTION:
# This script checks for an installed Nessus Agent, verifies the version,
# and performs DNS checks and linking to the Nessus Agent Cluster.
# If the agent is outdated, it is replaced with a provided RPM.
# Includes retry logic for unlink and link commands.
########################################################################################################################
 
# CONFIGURATION
MANAGER="nessus-manager.example.com"
MANAGER_IP="321.45.79.23"
LINKING_KEY="base64encodedlinkingkeytoobfuscatetheactualkey=="
GROUP="'RHEL Agents'"
REQUIRED_VERSION="10.8.3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="$SCRIPT_DIR/nessus_agent_install.log"
 
# CHILD NODE DNS MAPPINGS
declare -A NODES=(
    ["nm424"]="321.45.79.24"
    ["nm425"]="321.45.79.25"
    ["nm426"]="321.45.79.26"
    ["nm427"]="321.45.79.27"
    ["nm428"]="321.45.79.28"
)
 
log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOGFILE"
}
 
retry_command() {
    local CMD="$1"
    local MAX_RETRIES=3
    local COUNT=0
    local SUCCESS=false
 
    while [[ $COUNT -lt $MAX_RETRIES ]]; do
        eval "$CMD"
        if [[ $? -eq 0 ]]; then
            SUCCESS=true
            break
        else
            log_message "Attempt $((COUNT+1)) failed for: $CMD"
            ((COUNT++))
            sleep 2
        fi
    done
 
    if [[ "$SUCCESS" == false ]]; then
        log_message "Command failed after $MAX_RETRIES attempts: $CMD"
        exit 1
    fi
}
 
cleanup() {
    log_message "Cleaning up temporary files..."
}
trap cleanup EXIT
 
# === 1. VALIDATE BASELINE REQUIREMENTS ===
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo or as root. Exiting."
    exit 1
fi
 
for cmd in rpm systemctl grep tee getent; do
    if ! command -v "$cmd" &>/dev/null; then
        log_message "Error: Required command '$cmd' is missing."
        exit 1
    fi
done
 
if [[ -z "$MANAGER" || -z "$LINKING_KEY" ]]; then
    log_message "Error: Required variables MANAGER and LINKING_KEY are not set. Exiting."
    exit 1
fi
 
OS_VERSION=$(rpm --eval '%{rhel}')
TARGET_ARCH=$(uname -m)
 
# === 2. CHECK IF NESSUS AGENT IS INSTALLED ===
if ! rpm -q NessusAgent &>/dev/null; then
    log_message "Nessus Agent is not currently installed. This server is out of scope. Exiting."
    exit 1
fi
 
INSTALLED_VERSION=$(rpm -q --queryformat '%{VERSION}' NessusAgent)
log_message "Installed Nessus Agent version: $INSTALLED_VERSION"
 
# === 3. CHECK FOR VALID RPM FILE ===
RPM_FILES=($(ls NessusAgent*.rpm 2>/dev/null))
if [[ ${#RPM_FILES[@]} -eq 0 ]]; then
    log_message "No RPM files found in current directory. Exiting."
    exit 1
fi
 
log_message "Found the following RPM files:"
for RPM in "${RPM_FILES[@]}"; do
    log_message "  - $RPM"
    RPM_ARCH=$(echo "$RPM" | grep -oE 'x86_64|aarch64|arm64|ppc64le')
    RPM_OS_VERSION=$(echo "$RPM" | grep -oE 'el7|el8|el9')
    RPM_VERSION=$(echo "$RPM" | grep -oP 'NessusAgent-\K[0-9]+\.[0-9]+\.[0-9]+')
 
    if [[ "$RPM_ARCH" == "$TARGET_ARCH" && "$RPM_OS_VERSION" == "el$OS_VERSION" && "$RPM_VERSION" == "$REQUIRED_VERSION" ]]; then
        MATCHING_RPM="$RPM"
        break
    fi
    [[ "$RPM_ARCH" == "$TARGET_ARCH" ]] && MATCHED_ARCH=true
    [[ "$RPM_OS_VERSION" == "el$OS_VERSION" ]] && MATCHED_OS=true
    [[ "$RPM_VERSION" == "$REQUIRED_VERSION" ]] && MATCHED_VER=true
 
done
 
if [[ -z "$MATCHING_RPM" ]]; then
    log_message "No matching RPM found that satisfies all conditions:"
    [[ -z "$MATCHED_ARCH" ]] && log_message "- Missing RPM for architecture: $TARGET_ARCH"
    [[ -z "$MATCHED_OS" ]] && log_message "- Missing RPM for OS version: el$OS_VERSION"
    [[ -z "$MATCHED_VER" ]] && log_message "- Missing RPM for version: $REQUIRED_VERSION"
    log_message "Exiting before making any changes."
    exit 1
fi
 
# === 4. CHECK LINK STATUS ===
AGENT_STATUS_CMD=$(sudo /opt/nessus_agent/sbin/nessuscli agent status)
if echo "$AGENT_STATUS_CMD" | grep -q -e "Linked to: None" -e "Not linked to a manager"; then
    IS_LINKED=false
else
    IS_LINKED=true
fi
 
# === 5. READY TO MAKE CHANGES ===
if [[ "$INSTALLED_VERSION" != "$REQUIRED_VERSION" ]]; then
    log_message "Unlinking agent..."
    $IS_LINKED && retry_command "sudo /opt/nessus_agent/sbin/nessuscli agent unlink"
 
    log_message "Uninstalling old Nessus Agent version..."
    sudo rpm -e NessusAgent # Add -vv for debugging
 
    log_message "Installing RPM: $MATCHING_RPM"
    sudo rpm -i --force "$MATCHING_RPM" # add -v for debugging
    sleep 10
    sudo systemctl enable nessusagent
    sudo systemctl start nessusagent
else
    log_message "Agent is up to date."
fi
 
# === 6. DNS FIXES ===
DNS_SUFFIX=$(grep -oP '(?<=search\s)[^\n]+' /etc/resolv.conf | awk '{print $1}')
[[ -z "$DNS_SUFFIX" ]] && log_message "Warning: No DNS search suffix found in /etc/resolv.conf"
 
if ! getent hosts "$MANAGER" &>/dev/null; then
    log_message "Adding $MANAGER to /etc/hosts"
    echo "$MANAGER_IP $MANAGER" | sudo tee -a /etc/hosts
fi
 
RESOLVED=false
for NODE in "${!NODES[@]}"; do
    if getent hosts "$NODE" &>/dev/null; then
        RESOLVED=true
        break
    fi
    log_message "Unresolved: $NODE"
done
 
if [[ "$RESOLVED" == false ]]; then
    log_message "No nodes resolved. Adding all to /etc/hosts..."
    for NODE in "${!NODES[@]}"; do
        echo "${NODES[$NODE]} $NODE" | sudo tee -a /etc/hosts
    done
fi
 
# === 7. LINK AGENT ===
KEY=$(echo "$LINKING_KEY" | base64 -d)
log_message "Linking Nessus Agent to manager..."
retry_command "sudo /opt/nessus_agent/sbin/nessuscli agent link --host=\"$MANAGER\" --key=\"$KEY\" --port=8834 --groups=\"$GROUP\""
 
log_message "Nessus Agent status:"
sudo /opt/nessus_agent/sbin/nessuscli agent status --show-uuid
sudo /opt/nessus_agent/sbin/nessuscli -v
log_message "Process is complete."
 
######################################################################################################################
# - Handle and store this script securely.
# - Do not share with unauthorized personnel.
# - Ensure compliance with all applicable regulations.
######################################################################################################################
