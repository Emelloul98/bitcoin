#!/bin/bash

# Try to stop bitcoind gracefully if it's running
if pgrep -x "bitcoind" > /dev/null
then
    src/bitcoin-cli -regtest stop
    sleep 2
    while pgrep -x "bitcoind" > /dev/null; do
        sleep 1
    done
fi

rm -rf ~/.bitcoin/regtest

src/bitcoind -regtest -daemon -fallbackfee=0.001
sleep 3  # Wait for the server to start

src/bitcoin-cli -regtest createwallet "wallet1"
src/bitcoin-cli -regtest createwallet "wallet2"
src/bitcoin-cli -regtest createwallet "temp"


# Check the initial balances of the wallets
echo "Checking initial balances..."
src/bitcoin-cli -regtest -rpcwallet="wallet1" getbalance
src/bitcoin-cli -regtest -rpcwallet="wallet2" getbalance

# Create a new address for receiving Bitcoin in the "wallet1"
WALLET1=$(src/bitcoin-cli -regtest -rpcwallet="wallet1" getnewaddress)
echo "wallet1 address: $WALLET1"

# Get a new address from the second wallet ("wallet2")
WALLET2=$(src/bitcoin-cli -regtest -rpcwallet="wallet2" getnewaddress)
echo "wallet2 address: $WALLET2"

TEMP=$(src/bitcoin-cli -regtest -rpcwallet="temp" getnewaddress)

# Mine 101 blocks and assign them to the new wallet address
echo "Mining 1 block..."
src/bitcoin-cli -regtest generatetoaddress 1 "$WALLET1"
src/bitcoin-cli -regtest generatetoaddress 100 "$TEMP" > /dev/null
echo "wallet1 balance:"
src/bitcoin-cli -regtest -rpcwallet="wallet1" getbalance

# Send 1 BTC from "newtestwallet" to "testwallet"
echo "Sending 1 BTC from wallet1 to wallet2..."
src/bitcoin-cli -regtest -rpcwallet="wallet1" sendtoaddress "$WALLET2" 1

src/bitcoin-cli -regtest generatetoaddress 1 "$TEMP" > /dev/null

echo "Final balances:"
src/bitcoin-cli -regtest -rpcwallet="wallet1" getbalance
src/bitcoin-cli -regtest -rpcwallet="wallet2" getbalance

echo "Setup complete!"
