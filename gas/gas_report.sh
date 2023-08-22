forge build
forge test --gas-report --match-path test/foundry/KernelECDSA.t.sol > gas/ecdsa/report.txt
forge test --gas-report --match-path test/foundry/KernelLiteECDSA.t.sol > gas/ecdsa/report-lite.txt
