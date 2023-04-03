#!/bin/bash -xe
#echo prepack for "contracts" package

npx hardhat clean 
npx hardhat compile


rm -rf artifacts-selected types dist

mkdir -p artifacts-selected
cp `find  ./artifacts/src ./artifacts/lib -type f | grep -v -E 'Test|dbg|bls|IOracle'` artifacts-selected
npx typechain --target ethers-v5 --out-dir types  artifacts-selected/**
npx tsc index.ts -d --outDir dist
