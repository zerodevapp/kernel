forge build
forge test --gas-report --match-path test/foundry/Kernel.t.sol > gas/ecdsa/report.txt
forge test --gas-report --match-path test/foundry/KernelLite.t.sol > gas/ecdsa/report-lite.txt
