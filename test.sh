#!/usr/bin/env bash

# Colors for test output
GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Utility function to print test results
print_test_result() {
    local test_name="$1"
    local result="$2"
    local message="${3:-}"
    
    if [ "$result" -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${RESET}: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${RESET}: $test_name"
        if [ -n "$message" ]; then
            echo "  Error: $message"
        fi
        ((TESTS_FAILED++))
    fi
}

# New function that performs the grep check internally
assert_contains() {
    local output="$1"
    local expected="$2"
    local test_name="$3"
    
    if echo "$output" | grep -q "$expected"; then
        print_test_result "$test_name" 0
    else
        print_test_result "$test_name" 1 "Expected output '$expected' not found"
    fi
}


# Test the offline safe transaction hash calculation (raw data)
test_tx_offline_raw_data() {
    # Run the script and capture output
    local output
    output=$(./safe_hashes.sh tx --offline \
        --network sepolia \
        --safe-address 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F \
        --nonce 6 \
        --to 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9 \
        --data 0x095ea7b3000000000000000000000000fe2f653f6579de62aaf8b186e618887d03fa31260000000000000000000000000000000000000000000000000000000000000001) || true

    # Use assert_contains to perform all hash checks
    assert_contains "$output" "0xE411DFD2D178C853945BE30E1CEFBE090E56900073377BA8B8D0B47BAEC31EDB" "Domain Hash Check"
    assert_contains "$output" "0x4BBDE73F23B1792683730E7AE534A56A0EFAA8B7B467FF605202763CE2124DBC" "Message Hash Check"
    assert_contains "$output" "0x213be037275c94449a28b4edead76b0d63c7e12b52257f9d5686d98b9a1a5ff4" "Safe Transaction Hash Check"
}


# Test the JSON transaction hash calculation
test_tx_json_file() {
    local output
    output=$(./safe_hashes.sh tx --json-file ./reference/sample-transaction.json --nonce 20) || true

    assert_contains "$output" "Domain hash: 0x708A56F0D03FF6C322A52B593DD80A125C2C0CB4CB882FF7E9A25A245720E362" "JSON Domain Hash Check"
    assert_contains "$output" "Message hash: 0x49CD09CDE8E81A1D9F02B9EDB968AAAD8FA8453E3C7995A363A7A4F9E6CC62EB" "JSON Message Hash Check"
    assert_contains "$output" "Safe transaction hash: 0x55033b096ddc591fe60524bf767c914254aa91f24d611a0c5e9e27ec3f2720f0" "JSON Safe Transaction Hash Check"
}

# Test the JSON batch transaction hash calculation
test_tx_json_batch() {
    local output
    output=$(./safe_hashes.sh tx --json-file ./reference/sample-batch-tx.json --nonce 20) || true

    assert_contains "$output" "Domain hash: 0x708A56F0D03FF6C322A52B593DD80A125C2C0CB4CB882FF7E9A25A245720E362" "JSON Batch Domain Hash Check"
    assert_contains "$output" "Message hash: 0xF5C58F7D34E4BEF900FE37D9F6D81729C9D7B97781AEBB3EB57953B46EFDB518" "JSON Batch Message Hash Check"
    assert_contains "$output" "Safe transaction hash: 0xa90dfdceeb1abf346c2999527a7f869c307b1d1931c0d8a3d7819e03cbdf5517" "JSON Batch Safe Transaction Hash Check"
}

# Test the offline message processing
test_msg_basic_offline() {
    local output
    output=$(./safe_hashes.sh msg --input-file reference/sample-message.txt --network sepolia --safe-address 0x4087d2046A7435911fC26DCFac1c2Db26957Ab72 --offline) || true

    assert_contains "$output" "Multisig address: 0x4087d2046A7435911fC26DCFac1c2Db26957Ab72" "Multisig Address Check"
    assert_contains "$output" "Message: Hi!" "Message Text Check"
    assert_contains "$output" "Raw message hash: 0xe975170fcc555824149e9e3aadc4a5276a12e3c3078f19a324756477d384104f" "Safe Message Check"
    assert_contains "$output" "Domain hash: 0x708A56F0D03FF6C322A52B593DD80A125C2C0CB4CB882FF7E9A25A245720E362" "Domain Hash Check"
    assert_contains "$output" "Message hash: 0x4F340AB54BB3E34158DFDAA03F171570AAAF944642982283E5CE81A42CD7F743" "Message Hash Check"
    assert_contains "$output" "Safe message hash: 0x3a137c1cd9159ba93793e06450ad3f921bc0d2e37b57762e6642d8428a9edf0f" "Safe Message Hash Check"
}


# # Integration tests
# # Test the Arbitrum transaction hash calculation
# test_tx_arbitrum() {
#     local output
#     output=$(./safe_hashes.sh tx --network arbitrum --safe-address 0x111CEEee040739fD91D29C34C33E6B3E112F2177 --nonce 234) || true

#     # Check for the warning message (using single quotes to preserve the double quotes inside)
#     assert_contains "$output" 'WARNING: The "addOwnerWithThreshold" function modifies the owners or threshold of the Safe. Proceed with caution!' "Arbitrum Warning Check"
#     assert_contains "$output" "Domain hash: 0x1CF7F9B1EFE3BC47FE02FD27C649FEA19E79D66040683A1C86C7490C80BF7291" "Arbitrum Domain Hash Check"
#     assert_contains "$output" "Message hash: 0xD9109EA63C50ECD3B80B6B27ED5C5A9FD3D546C2169DFB69BFA7BA24CD14C7A5" "Arbitrum Message Hash Check"
#     assert_contains "$output" "Safe transaction hash: 0x0cb7250b8becd7069223c54e2839feaed4cee156363fbfe5dd0a48e75c4e25b3" "Arbitrum Safe Transaction Hash Check"
# }
# test_tx_arbitrum


# Run test
test_tx_offline_raw_data
test_tx_json_file
test_tx_json_batch
test_msg_basic_offline

# Print final results
echo
echo "Test Results:"
echo "============"
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${RESET}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${RESET}"

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1