#!/usr/bin/env bash

#################################################
# Script Name: safe_hashes.sh
# License: GNU Affero General Public License v3.0 only
# Authors: pcaversaccio, patrickalphac
# Dependencies: curl, jq, chisel, cast
#################################################

# ------------------------------------------------------------------
#                            CONSTANTS
# ------------------------------------------------------------------
readonly SCRIPT_VERSION="0.2.0"
readonly SCRIPT_NAME=$(basename "$0")
# Colors
readonly YELLOW="\e[33m"
readonly GREEN="\e[32m"
readonly RED="\e[31m"
readonly UNDERLINE="\e[4m"
readonly BOLD="\e[1m"
readonly RESET="\e[0m"
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

readonly SAFE_CLIENT_API_URL="https://safe-client.safe.global/v1/chains"
readonly DEFAULT_OFFLINE_SAFE_VERSION="1.3.0"

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
    ["scroll"]="https://safe-transaction-scroll.safe.global"
    ["sepolia"]="https://safe-transaction-sepolia.safe.global"
    ["worldchain"]="https://safe-transaction-worldchain.safe.global"
    ["xlayer"]="https://safe-transaction-xlayer.safe.global"
    ["zksync"]="https://safe-transaction-zksync.safe.global"
)

# MultiSend contract addresses by network
# https://github.com/safe-global/safe-deployments/blob/4e25b09f62a4acec92b4ebe6b8ae496b3852d440/src/assets/v1.4.1/multi_send_call_only.json
declare -A -r MULTISEND_CALL_ONLY_ADDRESSES_1_4_1=(
    ["arbitrum"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["aurora"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["avalanche"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["base"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["base-sepolia"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["blast"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["bsc"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["celo"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["ethereum"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["gnosis"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["gnosis-chiado"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["linea"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["mantle"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["optimism"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["polygon"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["polygon-zkevm"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["scroll"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["sepolia"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["worldchain"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    ["xlayer"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
    # ["zksync"]="0x9641d764fc13c8B624c04430C7356C1C7C8102e2"
)

# https://github.com/safe-global/safe-deployments/blob/4e25b09f62a4acec92b4ebe6b8ae496b3852d440/src/assets/v1.3.0/multi_send_call_only.json
declare -A -r MULTISEND_CALL_ONLY_ADDRESSES_1_3_0=(
    ["arbitrum"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["aurora"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["avalanche"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["base"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["base-sepolia"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["blast"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["bsc"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["celo"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["ethereum"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["gnosis"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["gnosis-chiado"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["linea"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["mantle"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["optimism"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["polygon"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["polygon-zkevm"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["scroll"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["sepolia"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["worldchain"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["xlayer"]="0x40A2aCCbd92BCA938b02010E17A5b8929b49130D"
    ["zksync"]="0xf220D3b4DFb23C4ade8C88E526C1353AbAcbC38F"
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
    ["scroll"]="534352"
    ["sepolia"]="11155111"
    ["worldchain"]="480"
    ["xlayer"]="196"
    ["zksync"]="324"
)

# ------------------------------------------------------------------
#                              SETUP
# ------------------------------------------------------------------
# Enable strict error handling:
# -E: Inherit `ERR` traps in functions and subshells.
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables as an error and exit.
# -o pipefail: Return the exit status of the first failed command in a pipeline.
set -Eeuo pipefail

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

# Enable debug mode if the environment variable `DEBUG` is set to `true`.
if [[ "${DEBUG:-false}" == "true" ]]; then
    # Print each command before executing it.
    set -x
fi


# ------------------------------------------------------------------
#                            FUNCTIONS
# ------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        usage 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version)
                echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"
                exit 0
                ;;
            --help)
                usage 0
                ;;
            tx|msg|list-networks)
                break
                ;;
            *)
                # If it's not a global option and not a subcommand, throw error
                echo -e "${BOLD}${RED}Unknown option: $1\nPlease run '${SCRIPT_NAME} --help' to see usage.${RESET}" >&2
                exit 1
                ;;
        esac
        shift
    done

    if [[ $# -eq 0 ]]; then
        echo -e "${BOLD}${RED}Error: A subcommand is required${RESET}" >&2
        usage
        exit 1
    fi

    # Process based on subcommand
    local subcommand="$1"
    shift

    case "$subcommand" in
        tx)
            handle_tx_command "$@"
            ;;
        msg)
            handle_msg_command "$@"
            ;;
        list-networks)
            list_networks
            ;;
        *)
            echo -e "${BOLD}${RED}Error: Unknown subcommand: ${subcommand}.\nPlease use ${SCRIPT_NAME} --help to see usage.${RESET}" >&2
            exit 1
            ;;
    esac
}

handle_msg_command () {
    local network="" address="" input_file="" offline=false version=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --offline) offline=true; shift ;;
            --network) network="$2"; shift 2 ;;
            --safe-address) address="$2"; shift 2 ;;
            --input-file) input_file="$2"; shift 2 ;;
            --safe-version) version="$2"; shift 2 ;;
            *) echo "Unknown option: $1" >&2; usage ;;
        esac
    done

    validate_network "$network"
    validate_address "$address"
    local chain_id=$(get_chain_id "$network")
    local api_url=""

    # Only get api_url and version in online mode or for message files
    if [[ "$offline" != true ]]; then
        # Get the API URL and response body
        read api_url response_body < <(get_api_url_and_response "$network" "$address")

        # Check if we're using the client API and need version from the command line
        if [[ "$api_url" == "$SAFE_CLIENT_API_URL" ]]; then
            if [[ -z "$version" ]]; then
                echo -e "${RED}Error: When using the client API, you must specify the Safe version. For example, use --safe-version \"1.3.0\"${RESET}" >&2
                exit 1
            fi
        else
            # Warn if a version was already set and will be overridden
            if [[ -n "$version" ]]; then
                echo -e "${YELLOW}Warning: Overriding previously set version with value from API response${RESET}" >&2
            fi
            # Extract version from the API response (defaults to "0.0.0" if not present)
            version=$(echo "$response_body" | jq -r '.version // "0.0.0"')
        fi
    fi
    if [[ -z "$version" || "$version" == "0.0.0" ]]; then
        version="$DEFAULT_OFFLINE_SAFE_VERSION"
        echo -e "${YELLOW}Warning: Using default version $DEFAULT_OFFLINE_SAFE_VERSION${RESET}" >&2
    fi

    calculate_offchain_message_hashes "$network" "$chain_id" "$address" "$input_file" "$version" 
    exit 0
}

# Handle transaction hash calculation subcommand
handle_tx_command() {
    local network="" address="" nonce="" offline=false version="" untrusted=false json_file=""
    local offline_to="" offline_value="0" offline_data="0x" offline_operation="0"
    local offline_safe_tx_gas="0" offline_base_gas="0" offline_gas_price="0"
    local offline_gas_token="0x0000000000000000000000000000000000000000"
    local offline_refund_receiver="0x0000000000000000000000000000000000000000"
    local print_mst_calldata=false

    # Flags to track which transaction-specific parameters were provided
    local tx_params_provided=false to_set=false value_set=false data_set=false operation_set=false

    # Parse command line arguments for tx subcommand
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --network) network="$2"; shift 2 ;;
            --safe-address) address="$2"; shift 2 ;;
            --nonce) nonce="$2"; nonce_set=true; shift 2 ;;
            --json-file) json_file="$2"; shift 2 ;;
            --offline) offline=true; shift ;;
            --print-mst-calldata) print_mst_calldata=true; shift ;;
            --untrusted) untrusted=true; shift ;;
            --safe-version) version="$2"; shift 2 ;;
            --to) offline_to="$2"; tx_params_provided=true; to_set=true; shift 2 ;;
            --value) offline_value="$2"; tx_params_provided=true; value_set=true; shift 2 ;;
            --data) offline_data="$2"; tx_params_provided=true; data_set=true; shift 2 ;;
            --operation) offline_operation="$2"; tx_params_provided=true; operation_set=true; shift 2 ;;
            --safe-tx-gas) offline_safe_tx_gas="$2"; shift 2 ;;
            --base-gas) offline_base_gas="$2"; shift 2 ;;
            --gas-price) offline_gas_price="$2"; shift 2 ;;
            --gas-token) offline_gas_token="$2"; shift 2 ;;
            --refund-receiver) offline_refund_receiver="$2"; shift 2 ;;
            *)
                echo -e "${BOLD}${RED}Unknown option for tx command: $1${RESET}" >&2
                usage 1
                exit 1
                ;;
        esac
    done

    # Check for conflicting options: JSON file and transaction parameters
    if [[ -n "$json_file" && "$tx_params_provided" = true ]]; then
        echo -e "${BOLD}${YELLOW}Warning: Using --json-file together with either to, value, data, or operation parameters, which may cause unexpected results${RESET}" >&2
    fi

    # If network is not provided but JSON file is, try to get network from chain ID in JSON
    if [[ -z "$network" && -n "$json_file" ]]; then
        # Check if the file exists
        if [[ -f "$json_file" ]]; then
            local file_chain_id=$(jq -r '.chainId // ""' "$json_file")
            if [[ -n "$file_chain_id" && "$file_chain_id" != "null" ]]; then
                # Check if chain ID exists in our chain IDs list
                local found_network=""
                for network_name in "${!CHAIN_IDS[@]}"; do
                    if [[ "${CHAIN_IDS[$network_name]}" == "$file_chain_id" ]]; then
                        found_network="$network_name"
                        break
                    fi
                done
                
                if [[ -n "$found_network" ]]; then
                    network="$found_network"
                    echo -e "${BOLD}${GREEN}Using network '$found_network' from chain ID $file_chain_id in the JSON file${RESET}"
                fi
            fi
        fi
    fi

    # If address is not provided but JSON file is, try to get Safe address from JSON
    if [[ -z "$address" && -n "$json_file" ]]; then
        # Check if the file exists
        if [[ -f "$json_file" ]]; then
            local file_address=$(jq -r '.meta.createdFromSafeAddress // ""' "$json_file")
            if [[ -n "$file_address" && "$file_address" != "null" && "$file_address" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
                address="$file_address"
                echo -e "${BOLD}${GREEN}Using Safe address '$file_address' from the JSON file${RESET}"
            fi
        fi
    fi

    # Validate required parameters
    if [[ -z "$network" || -z "$address" ]]; then
        echo -e "${BOLD}${RED}Error: network and address are required for tx command${RESET}" >&2
        usage
        exit 1
    fi

     # Validation
    if [[ "$offline" == true && "$print_mst_calldata" == true ]]; then
        echo -e "${RED}Error: The --print-mst-calldata option is not supported in offline mode. Please remove it and try again.${RESET}" >&2
        exit 1
    fi

    validate_network "$network"
    validate_address "$address"
    local chain_id=$(get_chain_id "$network")
    local api_url=""

    # Need to do this before the JSON processing
    if [[ "$offline" != true ]]; then
    # Get chain ID and API URL for the specified network
        local chain_id="$(get_chain_id "$network")"
        read api_url response_body < <(get_api_url_and_response "$network" "$address")
    
        # Check if we're using the client API and need version from the command line
        if [[ "$api_url" == "$SAFE_CLIENT_API_URL" ]]; then
            if [[ -z "$version" ]]; then
                echo -e "${RED}Error: When using the client API, you must specify the Safe version. For example, use --safe-version \"1.3.0\"${RESET}" >&2
                exit 1
            fi
        else
            # Warn if a version was already set and will be overridden
            if [[ -n "$version" ]]; then
                echo -e "${YELLOW}Warning: Overriding previously set version with value from API response${RESET}" >&2
            fi
            # Extract version from the API response (defaults to "0.0.0" if not present)
            version=$(echo "$response_body" | jq -r '.version // "0.0.0"')
        fi
        if [[ -z "$version" || "$version" == "0.0.0" ]]; then
            version="$DEFAULT_OFFLINE_SAFE_VERSION"
            echo -e "${YELLOW}Warning: Using default version $DEFAULT_OFFLINE_SAFE_VERSION${RESET}" >&2
        fi
    fi

    # Process JSON file if provided
    if [[ -n "$json_file" ]]; then
        if [[ ! -f "$json_file" ]]; then
            echo -e "${BOLD}${RED}Error: JSON file not found: ${json_file}${RESET}" >&2
            exit 1
        fi
        offline=true
    
        # should get offline_to, offline_value, offline_data, and offline_operation
        IFS=':' read -r json_to json_value json_data json_operation <<< "$(process_json_transactions "$json_file" "$version")"

        if [[ "$to_set" = false ]]; then
            offline_to="$json_to"
        fi
        if [[ "$value_set" = false ]]; then
            offline_value="$json_value"
        fi
        if [[ "$data_set" = false ]]; then
            offline_data="$json_data"
        fi
        if [[ "$operation_set" = false ]]; then
            offline_operation="$json_operation"
        fi
    fi

    # Validate nonce is provided
    if [[ -z "$nonce" ]]; then
        echo -e "${BOLD}${RED}Error: nonce is required for tx command${RESET}" >&2
        exit 1
    fi

    # Handle offline mode
    if [[ "$offline" == "true" ]]; then
        # Check that we have a destination address
        if [[ -z "$offline_to" ]]; then
            echo -e "${BOLD}${RED}Error: Target address (--to) is required for offline tx mode${RESET}" >&2
            exit 1
        fi
        
        # Call offline handler
        handle_tx_offline_mode "$network" "$chain_id" "$address" "$nonce" "$version" \
            "$offline_to" "$offline_value" "$offline_data" "$offline_operation" \
            "$offline_safe_tx_gas" "$offline_base_gas" "$offline_gas_price" \
            "$offline_gas_token" "$offline_refund_receiver"
    else
        # Call online handler
        handle_tx_online_mode "$network" "$chain_id" "$api_url" "$version" \
            "$address" "$nonce" "$untrusted" "$print_mst_calldata"
    fi
}

# Process a batch of transactions using MultiSend
process_json_transactions() {
    local json_file="$1"
    local safe_version="$2"
    
    # Get the total number of transactions in the batch
    local tx_count=$(jq '.transactions | length' "$json_file")
    
    if [[ $tx_count -eq 0 ]]; then
        echo -e "${BOLD}${RED}Error: No transactions found in the JSON file${RESET}" >&2
        exit 1
    fi

    local file_chain_id=$(jq -r '.chainId // ""' "$json_file")
    
    # If there's only one transaction, process it directly
    if [[ $tx_count -eq 1 ]]; then
        process_transaction_from_batch "$json_file" 0
    else
        # Process as a batch using MultiSend
        process_batch_transactions "$json_file" "$safe_version"
    fi
}

# Process a batch of transactions using MultiSend
process_batch_transactions() {
    local json_file="$1"
    local safe_version="$2"
    
    local tx_count=$(jq '.transactions | length' "$json_file")

    local multisend_address
    if [[ $safe_version =~ ^1\.3\. ]]; then
        multisend_address="${MULTISEND_CALL_ONLY_ADDRESSES_1_3_0[$network]}"
    else
        multisend_address="${MULTISEND_CALL_ONLY_ADDRESSES_1_4_1[$network]}"
    fi

    local batch_operation="1"
    local total_value=0

    # Encode all transactions and join them
    local encoded_transactions=""
    
    for ((i=0; i<tx_count; i++)); do
        # Parse the result to get to, value, and data, ignore operation
        IFS=':' read -r tx_to tx_value tx_data tx_operation <<< $(process_transaction_from_batch "$json_file" $i)
        
        # Add to total value
        total_value=$((total_value + tx_value))
        
        # Remove 0x prefix for data length calculation
        local tx_data_no_prefix="${tx_data#0x}"
        local tx_data_length=$((${#tx_data_no_prefix} / 2))  # Convert hex length to byte length
        
        # Encode this transaction in the MultiSend format
        # operation (1 byte) + to (20 bytes) + value (32 bytes) + data length (32 bytes) + data
        
        # 1. Operation byte (0 for call)
        local encoded_tx="00"  # Standard call
        
        # 2. To address (20 bytes)
        encoded_tx="${encoded_tx}${tx_to#0x}"
        
        # 3. Value (32 bytes)
        # Convert value to hex and pad to 32 bytes
        local value_hex=""
        value_hex=$(cast --to-uint256 "$tx_value")
        value_hex="${value_hex#0x}"
        encoded_tx="${encoded_tx}${value_hex}"
        
        # 4. Data length (32 bytes)
        # Convert data length to hex and pad to 32 bytes
        local data_length_hex=$(printf "%064x" "$tx_data_length")
        encoded_tx="${encoded_tx}${data_length_hex}"
        
        # 5. Data (without 0x prefix)
        encoded_tx="${encoded_tx}${tx_data_no_prefix}"
        
        # Add to encoded transactions
        encoded_transactions="${encoded_transactions}${encoded_tx}"
    done
    
    # Generate final MultiSend calldata
    local batch_data=$(cast calldata "multiSend(bytes)" "0x${encoded_transactions}")
    
    # Return the essential parameters
    echo "$multisend_address:$total_value:$batch_data:$batch_operation"
}

# Process a specific transaction from a batch
process_transaction_from_batch() {
    local json_file="$1"
    local index="$2"
    
    # Extract transaction details from the specified index
    local tx=$(jq ".transactions[$index]" "$json_file")
    
    # Get 'to' address
    local offline_to=$(echo "$tx" | jq -r '.to')
    
    # Get value (default to 0)
    local offline_value=$(echo "$tx" | jq -r '.value // "0"')
    
    # Handle data field
    if echo "$tx" | jq -e '.contractMethod' &>/dev/null; then
        # Need to construct data from contractMethod and contractInputsValues
        local method_name=$(echo "$tx" | jq -r '.contractMethod.name')
        local inputs=$(echo "$tx" | jq -r '.contractMethod.inputs')
        local input_values=$(echo "$tx" | jq -r '.contractInputsValues')
        
        # Construct the function signature
        local signature="$method_name("
        local types=()
        local values=()
        
        # Process each input parameter
        local count=$(echo "$inputs" | jq 'length')
        for ((i=0; i<count; i++)); do
            local param_name=$(echo "$inputs" | jq -r ".[$i].name")
            local param_type=$(echo "$inputs" | jq -r ".[$i].type")
            local param_value=$(echo "$input_values" | jq -r ".[\"$param_name\"]")
            
            types+=("$param_type")
            values+=("$param_value")
            
            if [[ $i -lt $((count-1)) ]]; then
                signature="${signature}${param_type},"
            else
                signature="${signature}${param_type})"
            fi
        done
        
        # Build the cast calldata command
        local cast_cmd="cast calldata \"$signature\""
        for val in "${values[@]}"; do
            cast_cmd="$cast_cmd \"$val\""
        done
        
        # Execute the cast command to get the calldata
        offline_data=$(eval "$cast_cmd")
    else
        # No data or method provided
        offline_data="0x"
    fi
    local offline_operation="0"
    echo "$offline_to:$offline_value:$offline_data:$offline_operation"
}

# Utility function to display the usage information.
usage() {
    local exit_code=${1:-1}  

    cat <<EOF
Usage: ${SCRIPT_NAME} [--help] [--version] <command> [OPTIONS]

Commands:
  tx               Calculate transaction hashes
  msg              Calculate message hashes
  list-networks    List all supported networks and their chain IDs
  
Global Options:
  --version             Display the script version
  --help                Display this help message
  --safe-version        Safe version (default: 1.3.0)

Transaction Hash Commands:
  ${SCRIPT_NAME} tx --network <network> --safe-address <address> --nonce <nonce> [OPTIONS]
  ${SCRIPT_NAME} tx --offline --network <network> --safe-address <address> --nonce <nonce> [OPTIONS]

Transaction Hash Options:
  --network <network>          Specify the network (required)
  --safe-address <address>     Specify the Safe multisig address (required)
  --nonce <nonce>              Specify the transaction nonce (required)
  --untrusted                  Use untrusted endpoint (adds trusted=false parameter to API calls)
  --offline                    Calculate transaction hash offline without using the Safe API
  --print-mst-calldata         Print the calldata for the entire multi-sig transaction

Additional options for offline transaction mode:
  --json-file <file>           Specify a JSON file containing transaction parameters
  --to <address>               Target address (required in offline mode)
  --value <wei>                Transaction value in wei (default: 0)
  --data <hex>                 Transaction data (default: 0x)
  --operation <type>           Operation type (default: 0)
  --safe-tx-gas <gas>          SafeTxGas (default: 0)
  --base-gas <gas>             BaseGas (default: 0)
  --gas-price <price>          GasPrice (default: 0)
  --gas-token <address>        Gas token address (default: 0x0000...0000)
  --refund-receiver <address>  Refund receiver address (default: 0x0000...0000)

Message Hash Commands:
  ${SCRIPT_NAME} msg --network <network> --safe-address <address> --input-file <file> [OPTIONS]

Message Hash Options:
  --network <network>          Specify the network (required)
  --safe-address <address>     Specify the Safe multisig address (required)
  --input-file <file>          Specify the message file (required)
  --offline                    Calculate message hash without using the Safe API

Examples:
  # Online transaction hash calculation (trusted by default):
  ${SCRIPT_NAME} tx --network ethereum --safe-address 0x1234...5678 --nonce 42

  # Online transaction hash calculation with untrusted endpoint:
  ${SCRIPT_NAME} tx --network ethereum --safe-address 0x1234...5678 --nonce 42 --untrusted

  # Off-chain message hash calculation:
  ${SCRIPT_NAME} msg --network ethereum --safe-address 0x1234...5678 --input-file message.txt

  # Offline transaction hash calculation:
  ${SCRIPT_NAME} tx --offline --network ethereum --safe-address 0x1234...5678 --to 0x9876...5432 \\
     --data 0x095e...0001 --value 1000000000000000000 --nonce 42

EOF
    exit ${exit_code}
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
calculate_safe_domain_hash() {
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
    local domain_hash=$(calculate_safe_domain_hash "$version" "$domain_separator_typehash" "$domain_hash_args")

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
        echo "Skipping decoded data, since raw data or a json file was passed"
    else
        print_decoded_data "$data_decoded"
    fi
    # Print the results with the same formatting for "Domain hash" and "Message hash" as a Ledger hardware device.
    print_hash_info "$domain_hash" "$message_hash" "$safe_tx_hash"
}


# Utility function to validate the network name.
validate_network() {
    local network="$1"
    if [[ -z "$network" ]]; then
        echo -e "${RED}Error: Network name cannot be empty${RESET}" >&2
        exit 1
    fi
    if [[ -z "${API_URLS[$network]:-}" || -z "${CHAIN_IDS[$network]:-}" ]]; then
        echo -e "${BOLD}${RED}Invalid network name: \"${network}\"${RESET}\n" >&2
        list_networks >&2
        exit 1
    fi
}

# Utility function to retrieve the API URL of the selected network.
get_api_url_and_response() {
    local network="$1"
    local address="$2"
    local api_url
    
    validate_network "$network"
    api_url="${API_URLS[$network]}"
    
    # Fetch the safe info and handle potential errors
    local safe_info_response
    local response_body
    local status_code
    
    safe_info_response=$(curl -s -w "\n%{http_code}" "${api_url}/api/v1/safes/${address}/")
    response_body=$(echo "$safe_info_response" | sed '$d')
    status_code=$(echo "$safe_info_response" | tail -n1)
    
    # If 404, try alternative API
    if [[ "$status_code" == "404" ]]; then
        echo -e "${YELLOW}Warning: 404 returned from Safe Transaction API. We will attempt to use the client API instead.${RESET}" >&2
        api_url="$SAFE_CLIENT_API_URL"
    fi
    
    # Check for empty response
    if [[ -z "$response_body" ]]; then
        echo -e "${RED}Error: Empty response from Safe API.\nYou can try again with '--offline' mode if you prefer.${RESET}" >&2
        exit 1
    fi
    
    # Keep this line like this to return the values, we use a space because URLs are hard
    echo "$api_url $response_body"
}

# Utility function to retrieve the chain ID of the selected network.
get_chain_id() {
    local network="$1"
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
validate_input_file() {
    local input_file="$1"
    if [[ ! -f "$input_file" ]]; then
        echo -e "${BOLD}${RED}Message file not found: \"${input_file}\"!${RESET}" >&2
        exit 1
    fi
    if [[ ! -s "$input_file" ]]; then
        echo -e "${BOLD}${RED}Message file is empty: \"${input_file}\"!${RESET}" >&2
        exit 1
    fi
}


# Utility function to calculate the domain and message hashes for off-chain messages.
calculate_offchain_message_hashes() {
    local network=$1
    local chain_id=$2
    local address=$3
    local input_file=$4
    local version=$5

    validate_input_file "$input_file"

    # Validate the Safe multisig version.
    validate_version "$version"

    local message_raw=$(< "$input_file")
    local hashed_message
    local message_hash
    local primary_type=""
    
    # Initialize variables
    local message_raw=$(< "$input_file")
    local hashed_message
    local message_hash
    local primary_type=""
    local domain_separator_typehash="$DOMAIN_SEPARATOR_TYPEHASH"
    local domain_hash_args="$domain_separator_typehash, $chain_id, $address"
    
    # Normalise line endings to `LF` (`\n`).
    message_raw=$(echo "$message_raw" | tr -d "\r")
    hashed_message=$(cast hash-message "$message_raw")
    
    # Calculate the message hash.
    message_hash=$(chisel eval "keccak256(abi.encode(bytes32($SAFE_MSG_TYPEHASH), keccak256(abi.encode(bytes32($hashed_message)))))" |
        awk '/Data:/ {gsub(/\x1b\[[0-9;]*m/, "", $3); print $3}')

    # Calculate the domain hash.
    local domain_hash=$(calculate_safe_domain_hash "$version" "$domain_separator_typehash" "$domain_hash_args")

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

handle_tx_online_mode() {
    # Get the API URL and chain ID for the specified network.
    local network="$1"
    local chain_id="$2"
    local api_url="$3"
    local version="$4"
    local address="$5"
    local nonce="$6"
    local untrusted="$7"
    local print_mst_calldata="$8"

    local endpoint

    if [[ "$api_url" == "$SAFE_CLIENT_API_URL" ]]; then
        # Use client API format
        endpoint="${api_url}/${chain_id}/safes/${address}/multisig-transactions/raw?nonce=${nonce}"
    else
        # Use transaction API format
        endpoint="${api_url}/api/v1/safes/${address}/multisig-transactions/?nonce=${nonce}"
        
        if [[ "$untrusted" == "true" ]]; then
            endpoint="${endpoint}&trusted=false"
        fi
    fi

    if [[ "$untrusted" == "true" ]]; then
        endpoint="${endpoint}&trusted=false"
    fi

    # Validate if the nonce parameter has the correct format.
    validate_nonce "$nonce"

    # Fetch the transaction data from the API.
    local response=$(curl -sf "$endpoint")

    # For debugging purposes:
    # echo "Endpoint: $endpoint"

    local count=$(echo "$response" | jq -r ".count // \"0\"")
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

    local to=$(echo "$response" | jq -r ".results[$idx].to // \"0x0000000000000000000000000000000000000000\"")
    local value=$(echo "$response" | jq -r ".results[$idx].value // \"0\"")
    local data=$(echo "$response" | jq -r ".results[$idx].data // \"0x\"")
    local operation=$(echo "$response" | jq -r ".results[$idx].operation // \"0\"")
    local safe_tx_gas=$(echo "$response" | jq -r ".results[$idx].safeTxGas // \"0\"")
    local base_gas=$(echo "$response" | jq -r ".results[$idx].baseGas // \"0\"")
    local gas_price=$(echo "$response" | jq -r ".results[$idx].gasPrice // \"0\"")
    local gas_token=$(echo "$response" | jq -r ".results[$idx].gasToken // \"0x0000000000000000000000000000000000000000\"")
    local refund_receiver=$(echo "$response" | jq -r ".results[$idx].refundReceiver // \"0x0000000000000000000000000000000000000000\"")
    local nonce=$(echo "$response" | jq -r ".results[$idx].nonce // \"0\"")
    local data_decoded=$(echo "$response" | jq -r ".results[$idx].dataDecoded // \"0x\"")
    local confirmations_required=$(echo "$response" | jq -r ".results[$idx].confirmationsRequired // \"0\"")
    local confirmation_count=$(echo "$response" | jq -r ".results[$idx].confirmations | length // \"0\"")

    # Extract signatures from confirmations array and concatenate them
    local signatures=$(echo "$response" | jq -r '.results[0].confirmations | reverse | .[].signature' | sed '1!s/0x//' | tr -d '\n')

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

handle_tx_offline_mode() {
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

    if [[ -z "$version" ]]; then
        version=$DEFAULT_OFFLINE_SAFE_VERSION
        echo -e "${YELLOW}Warning: No version detected. Using default version ${version}${RESET}" >&2
    fi

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
# calculate_safe_hashes "$@"

main "$@"