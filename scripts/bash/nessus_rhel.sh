#!/bin/bash

######################################################################################################################
# Nessus Agent Installation Script (RHEL / Oracle Linux)
# Author: Corderius Shepherd
# Version: 1.17
# Last Updated: 11-APR-2025
#
# DESCRIPTION:
# This script checks for an installed Nessus Agent, verifies the version,
# and performs DNS checks and linking to the Nessus Agent Cluster.
# If the agent is outdated, it is replaced with a provided RPM.
# Includes retry logic for unlink and link commands.
########################################################################################################################

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# CONFIGURATION
MANAGER="nessus-manager.example.com"
MANAGER_IP="321.45.79.23"
LINKING_KEY="REPLACE_WITH_BASE64_ENCODED_KEY"
GROUP="'RHEL Agents'"
REQUIRED_VERSION="10.8.3"

# CHILD NODE DNS MAPPINGS
declare -A NODES=(
    ["nm424"]="321.45.79.24"
    ["nm425"]="321.45.79.25"
    ["nm426"]="321.45.79.26"
    ["nm427"]="321.45.79.27"
    ["nm428"]="321.45.79.28"
)

# Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOGFILE="$SCRIPT_DIR/nessus_agent_install.log"
readonly BACKUP_DIR="$SCRIPT_DIR/backups"
readonly MAX_RETRIES=3
readonly RETRY_DELAY=2

# Logging levels
readonly LOG_LEVEL_DEBUG=0
readonly LOG_LEVEL_INFO=1
readonly LOG_LEVEL_WARNING=2
readonly LOG_LEVEL_ERROR=3

# Current log level
LOG_LEVEL=${LOG_LEVEL:-$LOG_LEVEL_INFO}

# Function to log messages with different levels
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local level_str

    case $level in
        $LOG_LEVEL_DEBUG) level_str="DEBUG" ;;
        $LOG_LEVEL_INFO) level_str="INFO" ;;
        $LOG_LEVEL_WARNING) level_str="WARNING" ;;
        $LOG_LEVEL_ERROR) level_str="ERROR" ;;
        *) level_str="UNKNOWN" ;;
    esac

    if [[ $level -ge $LOG_LEVEL ]]; then
        echo "$timestamp [$level_str] $message" | tee -a "$LOGFILE"
    fi
}

# Function to validate the linking key
validate_linking_key() {
    local key=$1
    if [[ -z "$key" ]]; then
        log_message $LOG_LEVEL_ERROR "Linking key is empty"
        return 1
    fi
    
    # Check if the key is valid base64
    if ! echo "$key" | base64 -d &>/dev/null; then
        log_message $LOG_LEVEL_ERROR "Invalid base64 encoding in linking key"
        return 1
    fi
    
    return 0
}

# Function to backup files
backup_file() {
    local file=$1
    local backup_path="$BACKUP_DIR/$(basename "$file").$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -p "$file" "$backup_path"
        log_message $LOG_LEVEL_INFO "Backed up $file to $backup_path"
    fi
}

# Function to restore from backup
restore_from_backup() {
    local file=$1
    local backup_path="$BACKUP_DIR/$(basename "$file").$(ls -t "$BACKUP_DIR/$(basename "$file")."* 2>/dev/null | head -n1)"
    
    if [[ -f "$backup_path" ]]; then
        cp -p "$backup_path" "$file"
        log_message $LOG_LEVEL_INFO "Restored $file from backup"
    fi
}

# Function to verify RPM integrity
verify_rpm() {
    local rpm_file=$1
    if ! rpm -K "$rpm_file" &>/dev/null; then
        log_message $LOG_LEVEL_ERROR "RPM integrity check failed: $rpm_file"
        return 1
    fi
    return 0
}

# Function to retry commands with exponential backoff
retry_command() {
    local cmd=$1
    local count=0
    local success=false
    local delay=$RETRY_DELAY

    while [[ $count -lt $MAX_RETRIES ]]; do
        if eval "$cmd"; then
            success=true
            break
        else
            log_message $LOG_LEVEL_WARNING "Attempt $((count+1)) failed for: $cmd"
            ((count++))
            sleep $delay
            ((delay *= 2))
        fi
    done

    if [[ "$success" == false ]]; then
        log_message $LOG_LEVEL_ERROR "Command failed after $MAX_RETRIES attempts: $cmd"
        return 1
    fi
    return 0
}

# Function to check system requirements
check_requirements() {
    local missing_deps=()
    
    for cmd in rpm systemctl grep tee getent openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_message $LOG_LEVEL_ERROR "Missing required dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    if [[ $EUID -ne 0 ]]; then
        log_message $LOG_LEVEL_ERROR "This script must be run with sudo or as root"
        return 1
    fi
    
    return 0
}

# Function to check and fix DNS resolution
fix_dns() {
    local manager=$1
    local manager_ip=$2
    local -n nodes=$3
    
    backup_file "/etc/hosts"
    
    # Check and fix manager resolution
    if ! getent hosts "$manager" &>/dev/null; then
        log_message $LOG_LEVEL_INFO "Adding $manager to /etc/hosts"
        echo "$manager_ip $manager" | tee -a /etc/hosts
    fi
    
    # Check and fix node resolution
    local resolved=false
    for node in "${!nodes[@]}"; do
        if getent hosts "$node" &>/dev/null; then
            resolved=true
            break
        fi
        log_message $LOG_LEVEL_WARNING "Unresolved: $node"
    done
    
    if [[ "$resolved" == false ]]; then
        log_message $LOG_LEVEL_INFO "Adding all nodes to /etc/hosts"
        for node in "${!nodes[@]}"; do
            echo "${nodes[$node]} $node" | tee -a /etc/hosts
        done
    fi
}

# Function to manage Nessus agent
manage_nessus_agent() {
    local installed_version
    local matching_rpm
    
    # Check if Nessus agent is installed
    if ! rpm -q NessusAgent &>/dev/null; then
        log_message $LOG_LEVEL_ERROR "Nessus Agent is not installed"
        return 1
    fi
    
    installed_version=$(rpm -q --queryformat '%{VERSION}' NessusAgent)
    log_message $LOG_LEVEL_INFO "Installed Nessus Agent version: $installed_version"
    
    # Find matching RPM
    local rpm_files=($(ls NessusAgent*.rpm 2>/dev/null))
    if [[ ${#rpm_files[@]} -eq 0 ]]; then
        log_message $LOG_LEVEL_ERROR "No RPM files found"
        return 1
    fi
    
    for rpm in "${rpm_files[@]}"; do
        if verify_rpm "$rpm"; then
            local rpm_arch=$(echo "$rpm" | grep -oE 'x86_64|aarch64|arm64|ppc64le')
            local rpm_os_version=$(echo "$rpm" | grep -oE 'el7|el8|el9')
            local rpm_version=$(echo "$rpm" | grep -oP 'NessusAgent-\K[0-9]+\.[0-9]+\.[0-9]+')
            
            if [[ "$rpm_arch" == "$(uname -m)" && 
                  "$rpm_os_version" == "el$(rpm --eval '%{rhel}')" && 
                  "$rpm_version" == "$REQUIRED_VERSION" ]]; then
                matching_rpm="$rpm"
                break
            fi
        fi
    done
    
    if [[ -z "$matching_rpm" ]]; then
        log_message $LOG_LEVEL_ERROR "No matching RPM found"
        return 1
    fi
    
    # Update if needed
    if [[ "$installed_version" != "$REQUIRED_VERSION" ]]; then
        log_message $LOG_LEVEL_INFO "Updating Nessus Agent..."
        
        # Unlink if needed
        if systemctl is-active nessusagent &>/dev/null; then
            retry_command "/opt/nessus_agent/sbin/nessuscli agent unlink"
        fi
        
        # Stop service
        systemctl stop nessusagent
        
        # Remove old version
        rpm -e NessusAgent
        
        # Install new version
        rpm -i --force "$matching_rpm"
        
        # Start service
        systemctl enable nessusagent
        systemctl start nessusagent
        
        # Wait for service to be ready
        sleep 10
    else
        log_message $LOG_LEVEL_INFO "Nessus Agent is up to date"
    fi
    
    return 0
}

# Main function
main() {
    log_message $LOG_LEVEL_INFO "Starting Nessus Agent installation/update process"
    
    # Check requirements
    if ! check_requirements; then
        exit 1
    fi
    
    # Validate linking key
    if ! validate_linking_key "$LINKING_KEY"; then
        exit 1
    fi
    
    # Fix DNS resolution
    fix_dns "$MANAGER" "$MANAGER_IP" NODES
    
    # Manage Nessus agent
    if ! manage_nessus_agent; then
        log_message $LOG_LEVEL_ERROR "Failed to manage Nessus agent"
        exit 1
    fi
    
    # Link agent
    local key=$(echo "$LINKING_KEY" | base64 -d)
    if ! retry_command "/opt/nessus_agent/sbin/nessuscli agent link --host=\"$MANAGER\" --key=\"$key\" --port=8834 --groups=\"$GROUP\""; then
        log_message $LOG_LEVEL_ERROR "Failed to link agent"
        exit 1
    fi
    
    # Verify installation
    log_message $LOG_LEVEL_INFO "Nessus Agent status:"
    /opt/nessus_agent/sbin/nessuscli agent status --show-uuid
    /opt/nessus_agent/sbin/nessuscli -v
    
    log_message $LOG_LEVEL_INFO "Process completed successfully"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_message $LOG_LEVEL_ERROR "Script failed with exit code $exit_code"
        # Restore backups if needed
        restore_from_backup "/etc/hosts"
    fi
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT

# Run main function
main

######################################################################################################################
# - Handle and store this script securely.
# - Do not share with unauthorized personnel.
# - Ensure compliance with all applicable regulations.
######################################################################################################################
