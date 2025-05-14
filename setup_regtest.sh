#!/bin/bash

#rm -rf ~/.bitcoin/regtest
rm -r ~/.bitcoin/regtest/wallets/wallet1
rm -r ~/.bitcoin/regtest/wallets/wallet2

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
if [ ! -d ~/.bitcoin/regtest/wallets/wallet1 ]; then
    echo "Creating wallet1..."
    src/bitcoin-cli -regtest createwallet "wallet1"
else
    echo "wallet1 already exists, loading it..."
fi

if [ ! -d ~/.bitcoin/regtest/wallets/wallet2 ]; then
    echo "Creating wallet2..."
    src/bitcoin-cli -regtest createwallet "wallet2"
else
    echo "wallet2 already exists, loading it..."
fi

## Load the wallets
#echo "Loading wallets..."
#src/bitcoin-cli -regtest loadwallet "wallet1"
#src/bitcoin-cli -regtest loadwallet "wallet2"

# Check the initial balances of the wallets
echo "Checking initial balances..."
src/bitcoin-cli -regtest -rpcwallet="wallet1" getbalance
src/bitcoin-cli -regtest -rpcwallet="wallet2" getbalance

# Create a new address for receiving Bitcoin in the "newtestwallet"
NEW_WALLET_ADDRESS=$(src/bitcoin-cli -regtest -rpcwallet="wallet1" getnewaddress)
echo "New wallet address: $NEW_WALLET_ADDRESS"

# Mine 101 blocks and assign them to the new wallet address
echo "Mining 101 block..."
src/bitcoin-cli -regtest generatetoaddress 101 "$NEW_WALLET_ADDRESS"

# Get a new address from the second wallet ("testwallet")
TEST_WALLET_ADDRESS=$(src/bitcoin-cli -regtest -rpcwallet="wallet2" getnewaddress)
echo "Test wallet address: $TEST_WALLET_ADDRESS"

# Send 1 BTC from "newtestwallet" to "testwallet"
echo "Sending 0.01 BTC from wallet1 to wallet2..."
src/bitcoin-cli -regtest -rpcwallet="wallet1" sendtoaddress "$TEST_WALLET_ADDRESS" 0.01

# Show the final balances after the transaction
echo "Final balances:"
src/bitcoin-cli -regtest -rpcwallet="wallet1" getbalance
src/bitcoin-cli -regtest -rpcwallet="wallet2" getbalance

echo "Setup complete!"
#-regtest -fallbackfee=0.01
