*Original work from the [pcaversaccio/safe-tx-hashes-util](https://github.com/pcaversaccio/safe-tx-hashes-util) repo. This has been forked from there.*

# Safe Multisig Transaction Hashes <!-- omit from toc -->

[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue)](https://www.gnu.org/licenses/agpl-3.0)

```console
|)0/\/'T TR|\_|5T, \/3R1FY! 🫡
```

This Bash [script](./safe_hashes.sh) calculates the Safe transaction hashes by retrieving transaction details from the [Safe transaction service API](https://docs.safe.global/core-api/transaction-service-overview) and computing both the domain and message hashes using the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) standard.

> [!NOTE]
> This Bash [script](./safe_hashes.sh) relies on the [Safe transaction service API](https://docs.safe.global/core-api/transaction-service-overview), which requires transactions to be proposed and _logged_ in the service before they can be retrieved. Consequently, the initial transaction proposer cannot access the transaction at the proposal stage, making this approach incompatible with 1-of-1 multisigs.[^1]

> [!IMPORTANT]
> All Safe multisig versions starting from `0.1.0` and newer are supported.

- [About](#about)
  - [Differences from the Original Repo](#differences-from-the-original-repo)
  - [Supported Networks](#supported-networks)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
    - [Legacy Ledger](#legacy-ledger)
    - [macOS Users: Upgrading Bash](#macos-users-upgrading-bash)
  - [Installation](#installation)
    - [Curl](#curl)
    - [Source](#source)
      - [Optional: Make it a CLI tool](#optional-make-it-a-cli-tool)
  - [Docker](#docker)
    - [Build](#build)
    - [Run](#run)
  - [Dev Container](#dev-container)
  - [Quickstart](#quickstart)
    - [Examples to try](#examples-to-try)
- [Usage - Safe API Transaction Hash Verification](#usage---safe-api-transaction-hash-verification)
  - [Already Initialized Transactions](#already-initialized-transactions)
  - [Not Initialized Transactions](#not-initialized-transactions)
- [Usage - Offline](#usage---offline)
  - [Safe Transaction Hashes](#safe-transaction-hashes)
  - [Safe Message Hashes](#safe-message-hashes)
- [Trust Assumptions](#trust-assumptions)
- [Testing](#testing)
- [Community-Maintained User Interface Implementations](#community-maintained-user-interface-implementations)
- [Acknowledgements](#acknowledgements)

# About

## Differences from the Original Repo
1. Support for not relying on the Safe API
2. Support for using "raw" calldata to verify transaction hashes
3. Support for using the Safe API for verifying transaction hashes before signing (using the `untrusted` flag)

## Supported Networks

- Arbitrum (identifier: `arbitrum`, chain ID: `42161`)
- Aurora (identifier: `aurora`, chain ID: `1313161554`)
- Avalanche (identifier: `avalanche`, chain ID: `43114`)
- Base (identifier: `base`, chain ID: `8453`)
- Base Sepolia (identifier: `base-sepolia`, chain ID: `84532`)
- Blast (identifier: `blast`, chain ID: `81457`)
- BSC (Binance Smart Chain) (identifier: `bsc`, chain ID: `56`)
- Celo (identifier: `celo`, chain ID: `42220`)
- Ethereum (identifier: `ethereum`, chain ID: `1`)
- Gnosis (identifier: `gnosis`, chain ID: `100`)
- Gnosis Chiado (identifier: `gnosis-chiado`, chain ID: `10200`)
- Linea (identifier: `linea`, chain ID: `59144`)
- Mantle (identifier: `mantle`, chain ID: `5000`)
- Optimism (identifier: `optimism`, chain ID: `10`)
- Polygon (identifier: `polygon`, chain ID: `137`)
- Polygon zkEVM (identifier: `polygon-zkevm`, chain ID: `1101`)
- Scroll (identifier: `scroll`, chain ID: `534352`)
- Sepolia (identifier: `sepolia`, chain ID: `11155111`)
- World Chain (identifier: `worldchain`, chain ID: `480`)
- X Layer (identifier: `xlayer`, chain ID: `196`)
- ZKsync Era (identifier: `zksync`, chain ID: `324`)

# Getting Started

## Requirements

- [foundry (`cast` and `chisel` in particular)](https://getfoundry.sh/)
  - You'll know you did it right if you can run `cast --version` and you see a response like `cast 0.3.0 (41c6653 2025-01-15T00:25:27.680061000Z`
- [bash](https://www.gnu.org/software/bash/)
  - You'll know you have it if you run `bash --version` and see a response like `GNU bash, version 5....`

*If you're using the Safe API features, you'll also need to be connected to the internet*

### Legacy Ledger

If you're using a ledger wallet, you'll also need access to `perl`. Most Linux and MacOS systems come with this pre-installed. If you are not using a Ledger Nano X, you can remove this section of the script:

```bash
local binary_literal=$(
    echo -n "${safe_tx_hash#0x}" | xxd -r -p | \
    perl -pe 's/([^[:print:]]|[\x80-\xff])/sprintf("\\x%02x",ord($1))/ge; s/([^ -~])/sprintf("\\x%02x",ord($1))/ge'
)

print_header "Legacy Ledger Format"
print_field "Binary string literal" "$binary_literal"
```


### macOS Users: Upgrading Bash

This [script](./safe_hashes.sh) requires Bash [`4.0`](https://tldp.org/LDP/abs/html/bashver4.html) or higher due to its use of associative arrays (introduced in Bash [`4.0`](https://tldp.org/LDP/abs/html/bashver4.html)). Unfortunately, macOS ships by default with Bash `3.2` due to licensing requirements. To use this [script](./safe_hashes.sh), install a newer version of Bash through [Homebrew](https://brew.sh):

1. Install [Homebrew](https://brew.sh) if you haven't already:

```console
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. Install the latest version of Bash:

```console
brew install bash
```

3. Add the new shell to the list of allowed shells:

**Apple Silicon processors**

```console
sudo bash -c 'echo /opt/homebrew/bin/bash >> /etc/shells'
```

**Intel processors**

```console
sudo bash -c 'echo /usr/local/bin/bash >> /etc/shells'
```

4. Optionally, make it your default shell:

**Apple Silicon processors**

```console
chsh -s /opt/homebrew/bin/bash
```

**Intel processors**

```console
chsh -s /usr/local/bin/bash
```

Then restart your terminal.

You can verify your Bash version after the installation:

```console
bash --version
```

## Installation

### Curl

```bash
curl -L https://raw.githubusercontent.com/cyfrin/safe-tx-hashes/main/install.sh | bash
```

### Source

You can run scripts directly from this repository.

```bash
git clone https://github.com/Cyfrin/safe-tx-hashes
cd safe-tx-hashes
```

#### Optional: Make it a CLI tool

First, make the script executable if it isn't already:

```bash
chmod +x safe_hashes.sh
```

Copy the script to /usr/local/bin (creating a simpler name without the .sh extension):

```bash
sudo cp safe_hashes.sh /usr/local/bin/safe_hashes
```

Ensure the script has the proper permissions:

```bash
sudo chmod 755 /usr/local/bin/safe_hashes
```

Now you can use the script from anywhere by just typing `safe_hashes`.

## Docker

### Build

```console
docker build -t safe_hashes .
```

### Run

```console
docker run -it safe_hashes  [--help] [--list-networks] --network <network> --address <address> --nonce <nonce> --message <file>
```

## Dev Container

Optionally, to run this in a dev container in VSCode, first install the [dev containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers), then use the command pallete after cloning and run:

```
> Dev Containers: Reopen in Container
```

And to use the script, you can run:

```console
./safe_hashes.sh --help
```

## Quickstart

```console
./safe_hashes.sh [--help] [--list-networks] --network <network> --address <address> --nonce <nonce> --message <file>
```

> [!TIP]
> The [script](./safe_hashes.sh) is already set as _executable_ in the repository, so you can run it immediately after cloning or pulling the repository without needing to change permissions.

To enable _debug mode_, set the `DEBUG` environment variable to `true` before running the [script](./safe_hashes.sh):

```console
DEBUG=true ./safe_hashes.sh ...
```

This will print each command before it is executed, which is helpful when troubleshooting.

### Examples to try

Go ahead and run these!

- Safe API: Already Initialized Transaction
```console
./safe_hashes.sh --network arbitrum --address 0x111CEEee040739fD91D29C34C33E6B3E112F2177 --nonce 234
```

- Safe API: Not Initialized Transaction
```console
./safe_hashes.sh --network sepolia --address 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F --nonce 7 --untrusted
```

- Offline Mode: Transaction Hash
```console
./safe_hashes.sh --offline --data 0x095ea7b3000000000000000000000000fe2f653f6579de62aaf8b186e618887d03fa31260000000000000000000000000000000000000000000000000000000000000001 --address 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F --network sepolia --nonce 6 --to 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9
```

- Offline Mode: Message Hash
```console
./safe_hashes.sh --network sepolia --address 0x657ff0D4eC65D82b2bC1247b0a558bcd2f80A0f1 --message message-example.txt --offline
```

# Usage - Safe API Transaction Hash Verification

## Already Initialized Transactions

To calculate the Safe transaction hashes for a specific transaction, you need to specify the `network`, `address`, and `nonce` parameters. An example:

```console
./safe_hashes.sh --network arbitrum --address 0x111CEEee040739fD91D29C34C33E6B3E112F2177 --nonce 234
```

The [script](./safe_hashes.sh) will output the domain, message, and Safe transaction hashes, allowing you to easily verify them against the values displayed on your Ledger hardware wallet screen:

```console
===================================
= Selected Network Configurations =
===================================

Network: arbitrum
Chain ID: 42161

========================================
= Transaction Data and Computed Hashes =
========================================

> Transaction Data:
Multisig address: 0x111CEEee040739fD91D29C34C33E6B3E112F2177
To: 0x111CEEee040739fD91D29C34C33E6B3E112F2177
Value: 0
Data: 0x0d582f130000000000000000000000000c75fa5a5f1c0997e3eea425cfa13184ed0ec9e50000000000000000000000000000000000000000000000000000000000000003
Encoded message: 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8000000000000000000000000111ceeee040739fd91d29c34c33e6b3e112f21770000000000000000000000000000000000000000000000000000000000000000b34f85cea7c4d9f384d502fc86474cd71ff27a674d785ebd23a4387871b8cbfe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea
Method: addOwnerWithThreshold
Parameters: [
  {
    "name": "owner",
    "type": "address",
    "value": "0x0c75Fa5a5F1C0997e3eEA425cFA13184ed0eC9e5"
  },
  {
    "name": "_threshold",
    "type": "uint256",
    "value": "3"
  }
]

WARNING: The "addOwnerWithThreshold" function modifies the owners or threshold of the Safe. Proceed with caution!

> Hashes:
Domain hash: 0x1CF7F9B1EFE3BC47FE02FD27C649FEA19E79D66040683A1C86C7490C80BF7291
Message hash: 0xD9109EA63C50ECD3B80B6B27ED5C5A9FD3D546C2169DFB69BFA7BA24CD14C7A5
Safe transaction hash: 0x0cb7250b8becd7069223c54e2839feaed4cee156363fbfe5dd0a48e75c4e25b3
```

> To see an example of a standard ETH transfer, run the command: `./safe_hashes.sh --network ethereum --address 0x8FA3b4570B4C96f8036C13b64971BA65867eEB48 --nonce 39` and review the output.

To list all supported networks:

```console
./safe_hashes.sh --list-networks
```

## Not Initialized Transactions

For transactions that have not been initialized yet, the steps are a little different. 

# Usage - Offline 

When passing the `--offline` flag.

## Safe Transaction Hashes

We can remove trust assumptions on the [Safe transaction service API](https://docs.safe.global/core-api/transaction-service-overview)!

You can optionally, run this script using the `--offline` subcommand. 

To calculate the Safe transaction hashes for a transaction that hasn't been initialized yet, or where you don't want to trust the safe transaction API, you can specify all the parameters. An example:

```console
./safe_hashes.sh --offline --data 0x095ea7b3000000000000000000000000fe2f653f6579de62aaf8b186e618887d03fa31260000000000000000000000000000000000000000000000000000000000000001 --address 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F --network sepolia --nonce 6 --to 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9
```

You can run `./safe_hashes.sh --offline --help` to see the available options.

The [script](./safe_hashes.sh) will output the domain, message, and Safe transaction hashes, allowing you to easily verify them against the values displayed on your Ledger hardware wallet screen:

```console
===================================
= Selected Network Configurations =
===================================

Network: sepolia
Chain ID: 11155111

========================================
= Transaction Data and Computed Hashes =
========================================

Transaction Data
Multisig address: 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F
To: 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9
Value: 0
Data: 0x095ea7b3000000000000000000000000fe2f653f6579de62aaf8b186e618887d03fa31260000000000000000000000000000000000000000000000000000000000000001
Encoded message: 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d80000000000000000000000007b79995e5f793a07bc00c21412e50ecae098e7f900000000000000000000000000000000000000000000000000000000000000001c62604b0ed9a9ec0e55efe8fb203b3029e147d994854cf0dd8a9fcf5b240d600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006
Skipping decoded data, since raw data was passed

Hashes
Domain hash: 0xE411DFD2D178C853945BE30E1CEFBE090E56900073377BA8B8D0B47BAEC31EDB
Message hash: 0x4BBDE73F23B1792683730E7AE534A56A0EFAA8B7B467FF605202763CE2124DBC
Safe transaction hash: 0x213be037275c94449a28b4edead76b0d63c7e12b52257f9d5686d98b9a1a5ff4
```

You can run this example to see the output.

```console
./safe_hashes.sh --offline --data 0x095ea7b3000000000000000000000000fe2f653f6579de62aaf8b186e618887d03fa31260000000000000000000000000000000000000000000000000000000000000001 --address 0x86D46EcD553d25da0E3b96A9a1B442ac72fa9e9F --network sepolia --nonce 6 --to 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9
```


## Safe Message Hashes

This [script](./safe_hashes.sh) not only calculates Safe transaction hashes but also supports computing the corresponding hashes for off-chain messages following the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) standard. To calculate the Safe message hashes for a specific message, specify the `network`, `address`, and `message` parameters. The `message` parameter must specify a valid file containing the raw message. This can be either the file name or a relative path (e.g., `path/to/message.txt`). Note that the [script](./safe_hashes.sh) normalises line endings to `LF` (`\n`) in the message file.

An example: Save the following message to a file named `message.txt`:

```txt
Welcome to OpenSea!

Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).

This request will not trigger a blockchain transaction or cost any gas fees.

Wallet address:
0x657ff0d4ec65d82b2bc1247b0a558bcd2f80a0f1

Nonce:
ea499f2f-fdbc-4d04-92c4-b60aba887e06
```

Then, invoke the following command:

```console
./safe_hashes.sh --network sepolia --address 0x657ff0D4eC65D82b2bC1247b0a558bcd2f80A0f1 --message message.txt
```

The [script](./safe_hashes.sh) will output the raw message, along with the domain, message, and Safe message hashes, allowing you to easily verify them against the values displayed on your Ledger hardware wallet screen:

```console
===================================
= Selected Network Configurations =
===================================

Network: sepolia
Chain ID: 11155111

====================================
= Message Data and Computed Hashes =
====================================

> Message Data:
Multisig address: 0x657ff0D4eC65D82b2bC1247b0a558bcd2f80A0f1
Message: Welcome to OpenSea!

Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).

This request will not trigger a blockchain transaction or cost any gas fees.

Wallet address:
0x657ff0d4ec65d82b2bc1247b0a558bcd2f80a0f1

Nonce:
ea499f2f-fdbc-4d04-92c4-b60aba887e06

> Hashes:
Raw message hash: 0xcb1a9208c1a7c191185938c7d304ed01db68677eea4e689d688469aa72e34236
Domain hash: 0x611379C19940CAEE095CDB12BEBE6A9FA9ABB74CDB1FBD7377C49A1F198DC24F
Message hash: 0xA5D2F507A16279357446768DB4BD47A03BCA0B6ACAC4632A4C2C96AF20D6F6E5
Safe message hash: 0x1866b559f56261ada63528391b93a1fe8e2e33baf7cace94fc6b42202d16ea08
```

> [!NOTE]
> If you do not pass `--offline` for this, the script will attempt to get the correct Safe version from the API. If you want this to be 100% offline, be sure to pass the `--offline` flag!

# Trust Assumptions 

1. You trust my [script](./safe_hashes.sh) 😃.
2. You trust Linux.
3. You trust [Foundry](https://github.com/foundry-rs/foundry).
4. You trust the [Safe transaction service API](https://docs.safe.global/core-api/transaction-service-overview).
   1. Unless using [offline mode](#usage---offline)
5. You trust your hardware wallet's screen.
   1. [Trezor](https://trezor.io/)
   2. [Keystone](https://keyst.one/)
   3. [Cypherock](https://www.cypherock.com/)
   4. [Ledger](https://www.ledger.com/academy/topics/ledgersolutions/ledger-wallets-secure-screen-security-model)

# Testing

As of today, we are trying to keep this repo as minimal as possible, and not use a real testing framework like [bats](https://github.com/bats-core/bats-core). The current test just runs a single offline mode test. We may expand this in the future. 

```
bash test.sh
```

# Community-Maintained User Interface Implementations

> [!IMPORTANT]
> Please be aware that user interface implementations may introduce additional trust assumptions, such as relying on `npm` dependencies that have not undergone thorough review. Always verify and cross-reference with the main [script](./safe_hashes.sh).

- [`safeutils.openzeppelin.com`](https://safeutils.openzeppelin.com):
  - Code: [`josepchetrit12/safe-tx-hashes-util`](https://github.com/OpenZeppelin/safe-utils)
  - Authors: [`josepchetrit12`](https://github.com/josepchetrit12), [`xaler5`](https://github.com/xaler5)

# Acknowledgements

- [pcaversaccio](https://github.com/pcaversaccio)
