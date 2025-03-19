#!/usr/bin/env bash
set -eo pipefail

echo "Installing safe_hashes..."

BASE_DIR="${XDG_CONFIG_HOME:-$HOME}"
CYFRIN_DIR="${CYFRIN_DIR:-"$BASE_DIR/.cyfrin"}"
CYFRIN_BIN_DIR="$CYFRIN_DIR/bin"

SAFE_HASHES_URL="https://raw.githubusercontent.com/cyfrin/safe-tx-hashes/main/safe_hashes.sh"
BIN_PATH="$CYFRIN_BIN_DIR/safe_hashes"

# Create the .cyfrin bin directory and binary if it doesn't exist.
mkdir -p "$CYFRIN_BIN_DIR"
curl -# -L "$SAFE_HASHES_URL" -o "$BIN_PATH"
chmod +x "$BIN_PATH"

# Store the correct profile file (i.e. .profile for bash or .zshrc for ZSH).
case $SHELL in
*/zsh)
    PROFILE="${ZDOTDIR-"$HOME"}/.zshenv"
    PREF_SHELL=zsh
    ;;
*/bash)
    PROFILE=$HOME/.bashrc
    PREF_SHELL=bash
    ;;
*/fish)
    PROFILE=$HOME/.config/fish/config.fish
    PREF_SHELL=fish
    ;;
*/ash)
    PROFILE=$HOME/.profile
    PREF_SHELL=ash
    ;;
*)
    echo "safe_hashes: could not detect shell, manually add ${CYFRIN_BIN_DIR} to your PATH."
    exit 1
esac

# Only add the bin directory if it isn't already in PATH.
if [[ ":$PATH:" != *":${CYFRIN_BIN_DIR}:"* ]]; then
    # Add the directory to the path and ensure the old PATH variables remain.
    if [[ "$PREF_SHELL" == "fish" ]]; then
        echo >> "$PROFILE" && echo "fish_add_path -a $CYFRIN_BIN_DIR" >> "$PROFILE"
    else
        echo >> "$PROFILE" && echo "export PATH=\"\$PATH:$CYFRIN_BIN_DIR\"" >> "$PROFILE"
    fi
fi

# Export the PATH directly in the current session
export PATH="$PATH:$CYFRIN_BIN_DIR"

# Check dependencies
declare -a REQUIRED_TOOLS=("curl" "jq" "chisel" "cast")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -ne 0 ]]; then
    echo -e "\nWarning: The following required tools are not installed:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo -e "\nPlease install them to use safe_hashes properly."
fi

echo -e "\nDetected your preferred shell is ${PREF_SHELL} and added safe_hashes to PATH."
echo "Run 'source ${PROFILE}' or start a new terminal session to use safe_hashes."
echo -e "\nThen you can run 'safe_hashes --help' to see available options."