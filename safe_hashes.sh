#!/usr/bin/env bash

########################
# Don't trust, verify! #
########################

# @license GNU Affero General Public License v3.0 only
# @author pcaversaccio

# Set the terminal formatting constants.
readonly GREEN="\e[32m"
readonly RED="\e[31m"
readonly UNDERLINE="\e[4m"
readonly BOLD="\e[1m"
readonly RESET="\e[0m"

# Check the Bash version compatibility.
if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    echo -e "${BOLD}${RED}Error: This script requires Bash 4.0 or higher.${RESET}"
    echo -e "${BOLD}${RED}Current version: $BASH_VERSION${RESET}"
    echo -e "${BOLD}${RED}Please upgrade your Bash installation.${RESET}"
    echo -e "${BOLD}${RED}If you've already upgraded via Homebrew, try running:${RESET}"
    echo -e "${BOLD}${RED}/opt/homebrew/bin/bash $0 $@${RESET}"
    exit 1
fi

# Utility function to ensure all required tools are installed.
check_required_tools() {
    local tools=("curl" "jq" "chisel" "cast")
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -ne 0 ]]; then
        echo -e "${BOLD}${RED}The following required tools are not installed:${RESET}"
        for tool in "${missing_tools[@]}"; do
            echo -e "${BOLD}${RED}  - $tool${RESET}"
        done
        echo -e "${BOLD}${RED}Please install them to run the script properly.${RESET}"
        exit 1
    fi
}

check_required_tools

# Enable strict error handling:
# -E: Inherit `ERR` traps in functions and subshells.
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables as an error and exit.
# -o pipefail: Return the exit status of the first failed command in a pipeline.
set -Eeuo pipefail

# Enable debug mode if the environment variable `DEBUG` is set to `true`.
if [[ "${DEBUG:-false}" == "true" ]]; then
    # Print each command before executing it.
    set -x
fi

# Set the type hash constants.
# => `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");`
# See: https://github.com/safe-global/safe-smart-account/blob/a0a1d4292006e26c4dbd52282f4c932e1ffca40f/contracts/Safe.sol#L54-L57.
readonly DOMAIN_SEPARATOR_TYPEHASH="0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"
# => `keccak256("EIP712Domain(address verifyingContract)");`
# See: https://github.com/safe-global/safe-smart-account/blob/703dde2ea9882a35762146844d5cfbeeec73e36f/contracts/GnosisSafe.sol#L20-L23.
readonly DOMAIN_SEPARATOR_TYPEHASH_OLD="0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749"
# => `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)");`
# See: https://github.com/safe-global/safe-smart-account/blob/a0a1d4292006e26c4dbd52282f4c932e1ffca40f/contracts/Safe.sol#L59-L62.
readonly SAFE_TX_TYPEHASH="0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
# => `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 dataGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)");`
# See: https://github.com/safe-global/safe-smart-account/blob/427d6f7e779431333c54bcb4d4cde31e4d57ce96/contracts/GnosisSafe.sol#L25-L28.
readonly SAFE_TX_TYPEHASH_OLD="0x14d461bc7412367e924637b363c7bf29b8f47e2f84869f4426e5633d8af47b20"
# => `keccak256("SafeMessage(bytes message)");`
# See: https://github.com/safe-global/safe-smart-account/blob/febab5e4e859e6e65914f17efddee415e4992961/contracts/libraries/SignMessageLib.sol#L12-L13.
readonly SAFE_MSG_TYPEHASH="0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca"

# Define the supported networks from the Safe transaction service.
# See https://docs.safe.global/core-api/transaction-service-supported-networks.
declare -A -r API_URLS=(
    ["arbitrum"]="https://safe-transaction-arbitrum.safe.global"
    ["aurora"]="https://safe-transaction-aurora.safe.global"
    ["avalanche"]="https://safe-transaction-avalanche.safe.global"
    ["base"]="https://safe-transaction-base.safe.global"
    ["base-sepolia"]="https://safe-transaction-base-sepolia.safe.global"
    ["blast"]="https://safe-transaction-blast.safe.global"
    ["bsc"]="https://safe-transaction-bsc.safe.global"
    ["celo"]="https://safe-transaction-celo.safe.global"
    ["ethereum"]="https://safe-transaction-mainnet.safe.global"
    ["gnosis"]="https://safe-transaction-gnosis-chain.safe.global"
    ["gnosis-chiado"]="https://safe-transaction-chiado.safe.global"
    ["linea"]="https://safe-transaction-linea.safe.global"
    ["mantle"]="https://safe-transaction-mantle.safe.global"
    ["optimism"]="https://safe-transaction-optimism.safe.global"
    ["polygon"]="https://safe-transaction-polygon.safe.global"
    ["polygon-zkevm"]="https://safe-transaction-zkevm.safe.global"
    ["rootstock"]="https://gateway.safe.rootstock.io"
    ["rootstock-testnet"]="https://gateway.safe.rootstock.io"
    ["scroll"]="https://safe-transaction-scroll.safe.global"
    ["sepolia"]="https://safe-transaction-sepolia.safe.global"
    ["worldchain"]="https://safe-transaction-worldchain.safe.global"
    ["xlayer"]="https://safe-transaction-xlayer.safe.global"
    ["zksync"]="https://safe-transaction-zksync.safe.global"
)

# Define the chain IDs of the supported networks from the Safe transaction service.
declare -A -r CHAIN_IDS=(
    ["arbitrum"]="42161"
    ["aurora"]="1313161554"
    ["avalanche"]="43114"
    ["base"]="8453"
    ["base-sepolia"]="84532"
    ["blast"]="81457"
    ["bsc"]="56"
    ["celo"]="42220"
    ["ethereum"]="1"
    ["gnosis"]="100"
    ["gnosis-chiado"]="10200"
    ["linea"]="59144"
    ["mantle"]="5000"
    ["optimism"]="10"
    ["polygon"]="137"
    ["polygon-zkevm"]="1101"
    ["rootstock"]="30"
    ["rootstock-testnet"]="31"
    ["scroll"]="534352"
    ["sepolia"]="11155111"
    ["worldchain"]="480"
    ["xlayer"]="196"
    ["zksync"]="324"
)

version() {
    echo "safe_hashes 0.1.3"
    exit 0
}

# Utility function to display the usage information.
usage() {
    cat <<EOF
Usage: $0 [--help] [--list-networks]
       --network <network> --address <address> --nonce <nonce> [--untrusted]
       --message <file> print-mst-calldata
       $0 --offline --network <network> --address <address> --nonce <nonce> [OPTIONS]

Options:
  --version             Display the script version
  --help                Display this help message
  --list-networks       List all supported networks and their chain IDs
  --network <network>   Specify the network (required)
  --address <address>   Specify the Safe multisig address (required)
  --nonce <nonce>       Specify the transaction nonce (required for transaction hashes)
  --message <file>      Specify the message file (required for off-chain message hashes)
  --untrusted           Use untrusted endpoint (adds trusted=false parameter to API calls)
  --offline             Calculate transaction hash offline with custom parameters
  --print-mst-calldata  Print the calldata for the entire multi-sig transaction       

Additional options for offline mode:
  --to                  Target address (required in offline mode)
  --value               Transaction value in wei (default: 0)
  --data                Transaction data (default: 0x)
  --operation           Operation type (default: 0)
  --safe-tx-gas         SafeTxGas (default: 0)
  --base-gas            BaseGas (default: 0)
  --gas-price           GasPrice (default: 0)
  --gas-token           Gas token address (default: 0x0000...0000)
  --refund-receiver     Refund receiver address (default: 0x0000...0000)
  --safe-version        Safe version (default: 1.3.0)

Examples:
  # Online transaction hash calculation (trusted by default):
  $0 --network ethereum --address 0x1234...5678 --nonce 42

  # Online transaction hash calculation with untrusted endpoint:
  $0 --network ethereum --address 0x1234...5678 --nonce 42 --untrusted

  # Off-chain message hash calculation:
  $0 --network ethereum --address 0x1234...5678 --message message.txt

  # Offline transaction hash calculation:
  $0 --offline --network ethereum --address 0x1234...5678 --to 0x9876...5432 \\
     --data 0x095e...0001 --value 1000000000000000000 --nonce 42

EOF
    exit 1
}
# Utility function to list all supported networks.
list_networks() {
    echo "Supported Networks:"
    for network in $(echo "${!CHAIN_IDS[@]}" | tr " " "\n" | sort); do
        echo "  $network (${CHAIN_IDS[$network]})"
    done
    exit 0
}

# Utility function to print a section header.
print_header() {
    local header=$1
    if [[ -t 1 ]] && tput sgr0 >/dev/null 2>&1; then
        # Terminal supports formatting.
        printf "\n${UNDERLINE}%s${RESET}\n" "$header"
    else
        # Fallback for terminals without formatting support.
        printf "\n%s\n" "> $header:"
    fi
}

# Utility function to print a labelled value.
print_field() {
    local label=$1
    local value=$2
    local empty_line="${3:-false}"

    if [[ -t 1 ]] && tput sgr0 >/dev/null 2>&1; then
        # Terminal supports formatting.
        printf "%s: ${GREEN}%s${RESET}\n" "$label" "$value"
    else
        # Fallback for terminals without formatting support.
        printf "%s: %s\n" "$label" "$value"
    fi

    # Print an empty line if requested.
    if [[ "$empty_line" == "true" ]]; then
        printf "\n"
    fi
}

# Utility function to print the transaction data.
print_transaction_data() {
    local address=$1
    local to=$2
    local value=$3
    local data=$4
    local message=$5

    print_header "Transaction Data"
    print_field "Multisig address" "$address"
    print_field "To" "$to"
    print_field "Value" "$value"
    print_field "Data" "$data"
    print_field "Encoded message" "$message"
}

print_mst_calldata_data() {
    local to=$1
    local value=$2
    local data=$3
    local operation=$4
    local safe_tx_gas=$5
    local base_gas=$6
    local gas_price=$7
    local gas_token=$8
    local refund_receiver=$9
    local signatures=${10}
    local confirmations_required=${11}
    local confirmations_count=${12}

    print_header "Multi-sig Transaction Calldata Data"
    print_field "Confirmations count: " "$confirmations_count" 
    print_field "Required number: " "$confirmations_required"

    if [[ "$confirmations_count" -lt "$confirmations_required" ]]; then
        echo "Not enough confirmations to print calldata"
    else 
        local full_calldata=$(cast calldata "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)" \
            "$to" \
            "$value" \
            "$data" \
            "$operation" \
            "$safe_tx_gas" \
            "$base_gas" \
            "$gas_price" \
            "$gas_token" \
            "$refund_receiver" \
            "$signatures")
        print_field "Full transaction calldata" "$full_calldata"
        local tx_data_hashed=$(cast keccak "$data")
        print_field "Transaction calldata hash" "$tx_data_hashed"
    fi
}

# Utility function to format the hash (keep `0x` lowercase, rest uppercase).
format_hash() {
    local hash=$1
    local prefix="${hash:0:2}"
    local rest="${hash:2}"
    echo "${prefix,,}${rest^^}"
}

# Utility function to print the hash information.
print_hash_info() {
    local domain_hash=$1
    local message_hash=$2
    local safe_tx_hash=$3
    local binary_literal=$(
        echo -n "${safe_tx_hash#0x}" | xxd -r -p | \
        perl -pe 's/([^[:print:]]|[\x80-\xff])/sprintf("\\x%02x",ord($1))/ge; s/([^ -~])/sprintf("\\x%02x",ord($1))/ge'
    )

    print_header "Legacy Ledger Format"
    print_field "Binary string literal" "$binary_literal"

    print_header "Hashes"
    print_field "Domain hash" "$(format_hash "$domain_hash")"
    print_field "Message hash" "$(format_hash "$message_hash")"
    print_field "Safe transaction hash" "$safe_tx_hash"
}

# Utility function to print the ABI-decoded transaction data.
print_decoded_data() {
    local data_decoded=$1

    if [[ "$data_decoded" == "0x" ]]; then
        print_field "Method" "0x (ETH Transfer)"
        print_field "Parameters" "[]"
    else
        local method=$(echo "$data_decoded" | jq -r ".method")
        local parameters=$(echo "$data_decoded" | jq -r ".parameters")

        print_field "Method" "$method"
        print_field "Parameters" "$parameters"

        # Check if the called function is sensitive and print a warning in bold.
        case "$method" in
        addOwnerWithThreshold | removeOwner | swapOwner | changeThreshold)
            echo
            echo -e "${BOLD}${RED}WARNING: The \"$method\" function modifies the owners or threshold of the Safe. Proceed with caution!${RESET}"
            ;;
        esac

        # Check for sensitive functions in nested transactions.
        echo "$parameters" | jq -c ".[] | .valueDecoded[]? | select(.dataDecoded != null)" | while read -r nested_param; do
            nested_method=$(echo "$nested_param" | jq -r ".dataDecoded.method")

            if [[ "$nested_method" =~ ^(addOwnerWithThreshold|removeOwner|swapOwner|changeThreshold)$ ]]; then
                echo
                echo -e "${BOLD}${RED}WARNING: The \"$nested_method\" function modifies the owners or threshold of the Safe! Proceed with caution!${RESET}"
            fi
        done
    fi
}

# Utility function to extract the clean Safe multisig version.
get_version() {
    local version=$1
    # Safe multisig versions can have the format `X.Y.Z+L2`.
    # Remove any suffix after and including the `+` in the version string for comparison.
    local clean_version=$(echo "$version" | sed "s/+.*//")
    echo "$clean_version"
}

# Utility function to validate the Safe multisig version.
validate_version() {
    local version=$1
    if [[ -z "$version" ]]; then
        echo "$(tput setaf 3)No Safe multisig contract found for the specified network. Please ensure that you have selected the correct network.$(tput setaf 0)"
        exit 0
    fi

    local clean_version=$(get_version "$version")

    # Ensure that the Safe multisig version is `>= 0.1.0`.
    if [[ "$(printf "%s\n%s" "$clean_version" "0.1.0" | sort -V | head -n1)" == "$clean_version" && "$clean_version" != "0.1.0" ]]; then
        echo "$(tput setaf 3)Safe multisig version \"${clean_version}\" is not supported!$(tput setaf 0)"
        exit 0
    fi
}

# Utility function to calculate the domain hash.
calculate_domain_hash() {
    local version=$1
    local domain_separator_typehash=$2
    local domain_hash_args=$3

    # Validate the Safe multisig version.
    validate_version "$version"

    local clean_version=$(get_version "$version")

    # Safe multisig versions `<= 1.2.0` use a legacy (i.e. without `chainId`) `DOMAIN_SEPARATOR_TYPEHASH` value.
    # Starting with version `1.3.0`, the `chainId` field was introduced: https://github.com/safe-global/safe-smart-account/pull/264.
    if [[ "$(printf "%s\n%s" "$clean_version" "1.2.0" | sort -V | head -n1)" == "$clean_version" ]]; then
        domain_separator_typehash="$DOMAIN_SEPARATOR_TYPEHASH_OLD"
        domain_hash_args="$domain_separator_typehash, $address"
    fi

    # Calculate the domain hash.
    local domain_hash=$(chisel eval "keccak256(abi.encode($domain_hash_args))" |
        awk '/Data:/ {gsub(/\x1b\[[0-9;]*m/, "", $3); print $3}')
    echo "$domain_hash"
}

# Utility function to calculate the domain and message hashes.
calculate_hashes() {
    local chain_id=$1
    local address=$2
    local to=$3
    local value=$4
    local data=$5
    local operation=$6
    local safe_tx_gas=$7
    local base_gas=$8
    local gas_price=$9
    local gas_token=${10}
    local refund_receiver=${11}
    local nonce=${12}
    local data_decoded=${13}
    local version=${14}

    local domain_separator_typehash="$DOMAIN_SEPARATOR_TYPEHASH"
    local domain_hash_args="$domain_separator_typehash, $chain_id, $address"
    local safe_tx_typehash="$SAFE_TX_TYPEHASH"

    # Validate the Safe multisig version.
    validate_version "$version"

    local clean_version=$(get_version "$version")

    # Calculate the domain hash.
    local domain_hash=$(calculate_domain_hash "$version" "$domain_separator_typehash" "$domain_hash_args")

    # Calculate the data hash.
    # The dynamic value `bytes` is encoded as a `keccak256` hash of its content.
    # See: https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata.
    local data_hashed=$(cast keccak "$data")

    # Safe multisig versions `< 1.0.0` use a legacy (i.e. the parameter value `baseGas` was
    # called `dataGas` previously) `SAFE_TX_TYPEHASH` value. Starting with version `1.0.0`,
    # `baseGas` was introduced: https://github.com/safe-global/safe-smart-account/pull/90.
    if [[ "$(printf "%s\n%s" "$clean_version" "1.0.0" | sort -V | head -n1)" == "$clean_version" && "$clean_version" != "1.0.0" ]]; then
        safe_tx_typehash="$SAFE_TX_TYPEHASH_OLD"
    fi

    # Encode the message.
    local message=$(cast abi-encode "SafeTxStruct(bytes32,address,uint256,bytes32,uint8,uint256,uint256,uint256,address,address,uint256)" \
        "$safe_tx_typehash" \
        "$to" \
        "$value" \
        "$data_hashed" \
        "$operation" \
        "$safe_tx_gas" \
        "$base_gas" \
        "$gas_price" \
        "$gas_token" \
        "$refund_receiver" \
        "$nonce")

    # Calculate the message hash.
    local message_hash=$(cast keccak "$message")

    # Calculate the Safe transaction hash.
    local safe_tx_hash=$(chisel eval "keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), bytes32($domain_hash), bytes32($message_hash)))" |
        awk '/Data:/ {gsub(/\x1b\[[0-9;]*m/, "", $3); print $3}')

    # Print the retrieved transaction data.
    print_transaction_data "$address" "$to" "$value" "$data" "$message"

    # Print the ABI-decoded transaction data.
    if [[ "$data_decoded" == "{}" ]]; then
        echo "Skipping decoded data, since raw data was passed"
    else
        print_decoded_data "$data_decoded"
    fi
    # Print the results with the same formatting for "Domain hash" and "Message hash" as a Ledger hardware device.
    print_hash_info "$domain_hash" "$message_hash" "$safe_tx_hash"
}


# Utility function to validate the network name.
validate_network() {
    local network="$1"
    if [[ -z "${API_URLS[$network]:-}" || -z "${CHAIN_IDS[$network]:-}" ]]; then
        echo -e "${BOLD}${RED}Invalid network name: \"${network}\"${RESET}\n" >&2
        calculate_safe_hashes --list-networks >&2
        exit 1
    fi
}

# Utility function to retrieve the API URL of the selected network.
get_api_url() {
    local network="$1"
    validate_network "$network"
    echo "${API_URLS[$network]}"
}

# Utility function to retrieve the chain ID of the selected network.
get_chain_id() {
    local network="$1"
    validate_network "$network"
    echo "${CHAIN_IDS[$network]}"
}

# Utility function to validate the multisig address.
validate_address() {
    local address="$1"
    if [[ -z "$address" || ! "$address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
        echo -e "${BOLD}${RED}Invalid Ethereum address format: \"${address}\"${RESET}" >&2
        exit 1
    fi
}

# Utility function to validate the transaction nonce.
validate_nonce() {
    local nonce="$1"
    if [[ -z "$nonce" || ! "$nonce" =~ ^[0-9]+$ ]]; then
        echo -e "${BOLD}${RED}Invalid nonce value: \"${nonce}\". Must be a non-negative integer!${RESET}" >&2
        exit 1
    fi
}

# Utility function to validate the message file.
validate_message_file() {
    local message_file="$1"
    if [[ ! -f "$message_file" ]]; then
        echo -e "${BOLD}${RED}Message file not found: \"${message_file}\"!${RESET}" >&2
        exit 1
    fi
    if [[ ! -s "$message_file" ]]; then
        echo -e "${BOLD}${RED}Message file is empty: \"${message_file}\"!${RESET}" >&2
        exit 1
    fi
}

# Utility function to calculate the domain and message hashes for off-chain messages.
calculate_offchain_message_hashes() {
    local network=$1
    local chain_id=$2
    local address=$3
    local message_file=$4
    local version=$5

    validate_message_file "$message_file"

    # Validate the Safe multisig version.
    validate_version "$version"

    local message_raw=$(< "$message_file")
    # Normalise line endings to `LF` (`\n`).
    message_raw=$(echo "$message_raw" | tr -d "\r")
    local hashed_message=$(cast hash-message "$message_raw")

    local domain_separator_typehash="$DOMAIN_SEPARATOR_TYPEHASH"
    local domain_hash_args="$domain_separator_typehash, $chain_id, $address"

    # Calculate the domain hash.
    local domain_hash=$(calculate_domain_hash "$version" "$domain_separator_typehash" "$domain_hash_args")

    # Calculate the message hash.
    local message_hash=$(chisel eval "keccak256(abi.encode(bytes32($SAFE_MSG_TYPEHASH), keccak256(abi.encode(bytes32($hashed_message)))))" |
        awk '/Data:/ {gsub(/\x1b\[[0-9;]*m/, "", $3); print $3}')

    # Calculate the Safe message hash.
    local safe_msg_hash=$(chisel eval "keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), bytes32($domain_hash), bytes32($message_hash)))" |
        awk '/Data:/ {gsub(/\x1b\[[0-9;]*m/, "", $3); print $3}')

    # Calculate and display the hashes.
    echo "==================================="
    echo "= Selected Network Configurations ="
    echo -e "===================================\n"
    print_field "Network" "$network"
    print_field "Chain ID" "$chain_id" true
    echo "===================================="
    echo "= Message Data and Computed Hashes ="
    echo "===================================="
    print_header "Message Data"
    print_field "Multisig address" "$address"
    print_field "Message" "$message_raw"
    print_header "Hashes"
    print_field "Raw message hash" "$hashed_message"
    print_field "Domain hash" "$(format_hash "$domain_hash")"
    print_field "Message hash" "$(format_hash "$message_hash")"
    print_field "Safe message hash" "$safe_msg_hash"
}

# Safe Transaction/Message Hashes Calculator
# This function orchestrates the entire process of calculating the Safe transaction/message hashes:
# 1. Parses command-line arguments (`network`, `address`, `nonce`, `message`).
# 2. Validates that all required parameters are provided.
# 3. Retrieves the API URL and chain ID for the specified network.
# 4. Constructs the API endpoint URL.
# 5. If a message file is provided:
#    - Validates that no nonce is specified (as it's not applicable for off-chain message hashes).
#    - Calls `calculate_offchain_message_hashes` to compute and display the message hashes.
# 6. If a nonce is provided:
#    - Fetches the transaction data from the Safe transaction service API.
#    - Extracts the relevant transaction details from the API response.
#    - Calls the `calculate_hashes` function to compute and display the results.
calculate_safe_hashes() {
    # Display the help message if no arguments are provided.
    if [[ $# -eq 0 ]]; then
        usage
    fi

    local network="" address="" nonce="" message_file="" offline=false version="1.3.0" untrusted=false
    local offline_to="" offline_value="0" offline_data="0x" offline_operation="0"
    local offline_safe_tx_gas="0" offline_base_gas="0" offline_gas_price="0"
    local offline_gas_token="0x0000000000000000000000000000000000000000"
    local offline_refund_receiver="0x0000000000000000000000000000000000000000"
    local print_mst_calldata=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version) version ;;
            --help) usage ;;
            --offline) offline=true; shift ;;
            --print-mst-calldata) print_mst_calldata=true; shift ;;
            --untrusted) untrusted=true; shift ;;
            --network) network="$2"; shift 2 ;;
            --address) address="$2"; shift 2 ;;
            --nonce) nonce="$2"; shift 2 ;;
            --message) message_file="$2"; shift 2 ;;
            --to) offline_to="$2"; shift 2 ;;
            --value) offline_value="$2"; shift 2 ;;
            --data) offline_data="$2"; shift 2 ;;
            --operation) offline_operation="$2"; shift 2 ;;
            --safe-tx-gas) offline_safe_tx_gas="$2"; shift 2 ;;
            --base-gas) offline_base_gas="$2"; shift 2 ;;
            --gas-price) offline_gas_price="$2"; shift 2 ;;
            --gas-token) offline_gas_token="$2"; shift 2 ;;
            --refund-receiver) offline_refund_receiver="$2"; shift 2 ;;
            --safe-version) version="$2"; shift 2 ;;
            --list-networks) list_networks ;;
            *) echo "Unknown option: $1" >&2; usage ;;
        esac
    done

    # Validation
    if [[ "$offline" == true && "$print_mst_calldata" == true ]]; then
        echo -e "${RED}Error: The --print-mst-calldata option is not supported in offline mode. Please remove it and try again.${RESET}" >&2
        exit 1
    fi

    # Validate if the required parameters have the correct format.
    validate_network "$network"
    validate_address "$address"
    local chain_id=$(get_chain_id "$network")
    local api_url=""

    # Only get api_url and version in online mode or for message files
    if [[ "$offline" != "true" || -n "$message_file" ]]; then
        api_url=$(get_api_url "$network")
        if [[ "$network" == "rootstock" || "$network" == "rootstock-testnet" ]]; then
            version=$(curl -sf "${api_url}/v1/chains/${chain_id}/safes/${address}" | jq -r ".version // \"0.0.0\"")
        else
            version=$(curl -sf "${api_url}/api/v1/safes/${address}/" | jq -r ".version // \"0.0.0\"")
        fi
    fi

    # Handle message file mode first
    if [[ -n "$message_file" ]]; then
        if [[ -n "$nonce" ]]; then
            echo -e "${RED}Error: When calculating off-chain message hashes, do not specify a nonce.${RESET}" >&2
            exit 1
        fi
        calculate_offchain_message_hashes "$network" "$chain_id" "$address" "$message_file" "$version"
        exit 0
    fi

    if [[ "$offline" == true ]]; then
        handle_offline_mode "$network" "$chain_id" "$address" "$nonce" "$version" \
            "$offline_to" "$offline_value" "$offline_data" "$offline_operation" \
            "$offline_safe_tx_gas" "$offline_base_gas" "$offline_gas_price" \
            "$offline_gas_token" "$offline_refund_receiver"
    else
        handle_online_mode "$network" "$chain_id" "$api_url" "$version" \
            "$address" "$nonce" "$untrusted" "$print_mst_calldata"
    fi
}

handle_online_mode() {
    # Get the API URL and chain ID for the specified network.
    local network="$1"
    local chain_id="$2"
    local api_url="$3"
    local version="$4"
    local address="$5"
    local nonce="$6"
    local untrusted="$7"
    local print_mst_calldata="$8"

    local endpoint=""
    if [[ "$network" == "rootstock" || "$network" == "rootstock-testnet" ]]; then
        endpoint="${api_url}/v1/chains/${chain_id}/safes/${address}/multisig-transactions?nonce=${nonce}"
    else
        endpoint="${api_url}/api/v1/safes/${address}/multisig-transactions/?nonce=${nonce}"
    fi
    if [[ "$untrusted" == "true" ]]; then
        if [[ "$network" == "rootstock" || "$network" == "rootstock-testnet" ]]; then
            echo "$(tput setaf 1)Error: The --untrusted flag is not supported by Rootstock networks$(tput sgr0)" >&2
            exit 1
        fi
        endpoint="${endpoint}&trusted=false"
    fi

    # Validate if the nonce parameter has the correct format.
    validate_nonce "$nonce"

    # Fetch the transaction data from the API.
    local response=$(curl -sf "$endpoint")

    # For debugging purposes:
    # echo "Endpoint: $endpoint"

    local count=0
    if [[ "$network" == "rootstock" || "$network" == "rootstock-testnet" ]]; then
        count=$(echo "$response" | jq -r ".results | length // 0")
    else
        count=$(echo "$response" | jq -r ".count // \"0\"")
    fi
    local idx=0

    # Inform the user that no transactions are available for the specified nonce.
    if [[ $count -eq 0 ]]; then
        echo "$(tput setaf 3)No transaction is available for this nonce!$(tput setaf 0)"
        exit 0
    # Notify the user about multiple transactions with identical nonce values and prompt for user input.
    elif [[ $count -gt 1 ]]; then
        cat <<EOF
$(tput setaf 3)Several transactions with identical nonce values have been detected.
This occurrence is normal if you are deliberately replacing an existing transaction.
However, if your Safe interface displays only a single transaction, this could indicate
potential irregular activity requiring your attention.$(tput sgr0)

Kindly specify the transaction's array value (available range: 0-$((${count} - 1))).
You can find the array values at the following endpoint:
$(tput setaf 2)$endpoint$(tput sgr0)

Please enter the index of the array:
EOF

        while true; do
            read -r idx

            # Validate if user input is a number.
            if ! [[ $idx =~ ^[0-9]+$ ]]; then
                echo "$(tput setaf 1)Error: Please enter a valid number!$(tput sgr0)"
                continue
            fi

            local array_value=$(echo "$response" | jq ".results[$idx]")

            if [[ $array_value == null ]]; then
                echo "$(tput setaf 1)Error: No transaction found at index $idx. Please try again.$(tput sgr0)"
                continue
            fi

            printf "\n"

            break
        done
    fi

    local to="" value="" data="" operation="" safe_tx_gas="" base_gas="" gas_price="" gas_token="" refund_receiver="" data_decoded="{}"
    
    if [[ "$network" == "rootstock" || "$network" == "rootstock-testnet" ]]; then
        # Extract transaction ID from the first response
        local tx_id=$(echo "$response" | jq -r ".results[${idx}].transaction.id")
        
        # Fetch detailed transaction information
        local detailed_response=$(curl -sf "${api_url}/v1/chains/${chain_id}/transactions/${tx_id}")
        
        # Extract from Rootstock's detailed structure
        local tx_data=$(echo "$detailed_response" | jq -r ".txData")
        local detailed_execution_info=$(echo "$detailed_response" | jq -r ".detailedExecutionInfo")
        
        # Basic transaction details from txData
        to=$(echo "$tx_data" | jq -r ".to.value // \"0x0000000000000000000000000000000000000000\"")
        value=$(echo "$tx_data" | jq -r ".value // \"0\"")
        data=$(echo "$tx_data" | jq -r ".hexData // \"0x\"")
        operation=$(echo "$tx_data" | jq -r ".operation // \"0\"")
        data_decoded=$(echo "$tx_data" | jq -r ".dataDecoded // \"{}\"")
        
        # Execution details from detailedExecutionInfo
        safe_tx_gas=$(echo "$detailed_execution_info" | jq -r ".safeTxGas // \"0\"")
        base_gas=$(echo "$detailed_execution_info" | jq -r ".baseGas // \"0\"")
        gas_price=$(echo "$detailed_execution_info" | jq -r ".gasPrice // \"0\"")
        gas_token=$(echo "$detailed_execution_info" | jq -r ".gasToken // \"0x0000000000000000000000000000000000000000\"")
        refund_receiver=$(echo "$detailed_execution_info" | jq -r ".refundReceiver.value // \"0x0000000000000000000000000000000000000000\"")
        nonce=$(echo "$detailed_execution_info" | jq -r ".nonce // \"0\"")
        
        # Get confirmations info
        confirmations_required=$(echo "$detailed_execution_info" | jq -r ".confirmationsRequired // \"0\"")
        confirmation_count=$(echo "$detailed_execution_info" | jq -r ".confirmations | length // \"0\"")
        
        # Extract signatures - note the different path for Rootstock
        signatures=$(echo "$detailed_response" | jq -r '.detailedExecutionInfo.confirmations[].signature' | sed '1!s/0x//' | tr -d '\n')
    else
        # Original extraction for other networks
        to=$(echo "$response" | jq -r ".results[$idx].to // \"0x0000000000000000000000000000000000000000\"")
        value=$(echo "$response" | jq -r ".results[$idx].value // \"0\"")
        data=$(echo "$response" | jq -r ".results[$idx].data // \"0x\"")
        operation=$(echo "$response" | jq -r ".results[$idx].operation // \"0\"")
        safe_tx_gas=$(echo "$response" | jq -r ".results[$idx].safeTxGas // \"0\"")
        base_gas=$(echo "$response" | jq -r ".results[$idx].baseGas // \"0\"")
        gas_price=$(echo "$response" | jq -r ".results[$idx].gasPrice // \"0\"")
        gas_token=$(echo "$response" | jq -r ".results[$idx].gasToken // \"0x0000000000000000000000000000000000000000\"")
        refund_receiver=$(echo "$response" | jq -r ".results[$idx].refundReceiver // \"0x0000000000000000000000000000000000000000\"")
        nonce=$(echo "$response" | jq -r ".results[$idx].nonce // \"0\"")
        data_decoded=$(echo "$response" | jq -r ".results[$idx].dataDecoded // \"0x\"")
        confirmations_required=$(echo "$response" | jq -r ".results[$idx].confirmationsRequired // \"0\"")
        confirmation_count=$(echo "$response" | jq -r ".results[$idx].confirmations | length // \"0\"")
        
        # Extract signatures
        signatures=$(echo "$response" | jq -r '.results[0].confirmations | reverse | .[].signature' | sed '1!s/0x//' | tr -d '\n')
    fi

    # If signatures is empty, use 0x
    if [[ -z "$signatures" ]]; then
        signatures="0x"
    elif [[ ! "$signatures" =~ ^0x ]]; then
        signatures="0x${signatures}"
    fi

    # Calculate and display the hashes.
    echo "==================================="
    echo "= Selected Network Configurations ="
    echo -e "===================================\n"
    print_field "Network" "$network"
    print_field "Chain ID" "$chain_id" true
    echo "========================================"
    echo "= Transaction Data and Computed Hashes ="
    echo "========================================"
    calculate_hashes "$chain_id" \
        "$address" \
        "$to" \
        "$value" \
        "$data" \
        "$operation" \
        "$safe_tx_gas" \
        "$base_gas" \
        "$gas_price" \
        "$gas_token" \
        "$refund_receiver" \
        "$nonce" \
        "$data_decoded" \
        "$version" 

    if [[ "$print_mst_calldata" == "true" ]]; then
        print_mst_calldata_data "$to" "$value" "$data" "$operation" "$safe_tx_gas" "$base_gas" "$gas_price" "$gas_token" "$refund_receiver" "$signatures" "$confirmations_required" "$confirmation_count"
    fi

}

handle_offline_mode() {
    local network="$1"
    local chain_id="$2"
    local address="$3"
    local nonce="$4"
    local version="$5"
    local offline_to="$6"
    local offline_value="$7"
    local offline_data="$8"
    local offline_operation="$9"
    local offline_safe_tx_gas="${10}"
    local offline_base_gas="${11}"
    local offline_gas_price="${12}"
    local offline_gas_token="${13}"
    local offline_refund_receiver="${14}"

    if [[ -z "$network" || -z "$address" || -z "$offline_to" || -z "$nonce" ]]; then
        echo -e "${BOLD}${RED}Error: network, address, to, and nonce are required for offline mode${RESET}" >&2
        usage
    fi

    # Validate addresses
    validate_address "$offline_to"
    [[ "$offline_gas_token" != "0x0000000000000000000000000000000000000000" ]] && validate_address "$offline_gas_token"
    [[ "$offline_refund_receiver" != "0x0000000000000000000000000000000000000000" ]] && validate_address "$offline_refund_receiver"

    # Calculate and display the hashes
    echo "==================================="
    echo "= Selected Network Configurations ="
    echo -e "===================================\n"
    print_field "Network" "$network"
    print_field "Chain ID" "$chain_id" true
    echo "========================================"
    echo "= Transaction Data and Computed Hashes ="
    echo "========================================"
    calculate_hashes "$chain_id" \
        "$address" \
        "$offline_to" \
        "$offline_value" \
        "$offline_data" \
        "$offline_operation" \
        "$offline_safe_tx_gas" \
        "$offline_base_gas" \
        "$offline_gas_price" \
        "$offline_gas_token" \
        "$offline_refund_receiver" \
        "$nonce" \
        "{}" \
        "$version" 
}

# Entry point for the script
calculate_safe_hashes "$@"
