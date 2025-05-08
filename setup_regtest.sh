#!/bin/bash

# Check if bitcoind is already running
if pgrep -x "bitcoind" > /dev/null
then
    echo "bitcoind is already running."
else
    # Start bitcoind in regtest mode
    echo "Starting bitcoind..."
    src/bitcoind -regtest -daemon -fallbackfee=0.001
    sleep 3  # Wait for the server to start
fi

# Check if the wallets exist, if not create them
echo "Checking if wallets exist..."
if [ ! -d ~/.bitcoin/regtest/wallets/newtestwallet2 ]; then
    echo "Creating newtestwallet2..."
    src/bitcoin-cli -regtest createwallet "newtestwallet2"
else
    echo "newtestwallet2 already exists, loading it..."
fi

if [ ! -d ~/.bitcoin/regtest/wallets/testwallet2 ]; then
    echo "Creating testwallet2..."
    src/bitcoin-cli -regtest createwallet "testwallet2"
else
    echo "testwallet2 already exists, loading it..."
fi

## Load the wallets
echo "Loading wallets..."
src/bitcoin-cli -regtest loadwallet "newtestwallet2"
src/bitcoin-cli -regtest loadwallet "testwallet2"

# Check the initial balances of the wallets
echo "Checking initial balances..."
src/bitcoin-cli -regtest -rpcwallet="newtestwallet2" getbalance
src/bitcoin-cli -regtest -rpcwallet="testwallet2" getbalance

# Create a new address for receiving Bitcoin in the "newtestwallet"
NEW_WALLET_ADDRESS=$(src/bitcoin-cli -regtest -rpcwallet="newtestwallet2" getnewaddress)
echo "New wallet address: $NEW_WALLET_ADDRESS"

# Mine 101 blocks and assign them to the new wallet address
echo "Mining 101 blocks..."
src/bitcoin-cli -regtest generatetoaddress 101 "$NEW_WALLET_ADDRESS"

# Get a new address from the second wallet ("testwallet")
TEST_WALLET_ADDRESS=$(src/bitcoin-cli -regtest -rpcwallet="testwallet2" getnewaddress)
echo "Test wallet address: $TEST_WALLET_ADDRESS"

# Send 1 BTC from "newtestwallet" to "testwallet"
echo "Sending 1 BTC from newtestwallet2 to testwallet2..."
src/bitcoin-cli -regtest -rpcwallet="newtestwallet2" sendtoaddress "$TEST_WALLET_ADDRESS" 1

# Show the final balances after the transaction
echo "Final balances:"
src/bitcoin-cli -regtest -rpcwallet="newtestwallet2" getbalance
src/bitcoin-cli -regtest -rpcwallet="testwallet2" getbalance

echo "Setup complete!"
