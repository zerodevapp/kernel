pragma solidity ^0.8.0;

struct KernelStorage {
    address defaultValidator;
    address implementation;
}

contract KernelUpdater {
}
            /**
             * -------------------------------------------------------------------------------------+
             * CREATION (9 bytes)                                                                   |
             * -------------------------------------------------------------------------------------|
             * Opcode     | Mnemonic        | Stack               | Memory                          |
             * -------------------------------------------------------------------------------------|
             * 60 runSize | PUSH1 runSize   | r                   |                                 |
             * 3d         | RETURNDATASIZE  | 0 r                 |                                 |
             * 81         | DUP2            | r 0 r               |                                 |
             * 60 offset  | PUSH1 offset    | o r 0 r             |                                 |
             * 3d         | RETURNDATASIZE  | 0 o r 0 r           |                                 |
             * 39         | CODECOPY        | 0 r                 | [0..runSize): runtime code      |
             * f3         | RETURN          |                     | [0..runSize): runtime code      |
             * -------------------------------------------------------------------------------------|
             * RUNTIME (127 bytes)                                                                  |
             * -------------------------------------------------------------------------------------|
             * Opcode      | Mnemonic       | Stack               | Memory                          |
             * -------------------------------------------------------------------------------------|
             *                                                                                      |
             * ::: copy calldata to memory :::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 36          | CALLDATASIZE   | cds 0 0             |                                 |
             * 3d          | RETURNDATASIZE | 0 cds 0 0           |                                 |
             * 3d          | RETURNDATASIZE | 0 0 cds 0 0         |                                 |
             * 37          | CALLDATACOPY   | 0 0                 | [0..calldatasize): calldata     |
             *                                                                                      |
             * ::: keep some values in stack :::::::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 3d          | RETURNDATASIZE | 0 0 20              |                                 |
             * 3d          | RETURNDATASIZE | 0 0 0 20            |                                 |
             *                                                                                      |
             * ::: get implementation from factory :::::::::::::::::::::::::::::::::::::::::::::::: |
             * 73 factory  | PUSH20 factory | f 0 0 0 20          |                                 |
             * 3d          | GAS            | g f 0 0 0 20        |                                 |
             * 3d          | STATICCALL     | succ                |                                 |
             *                                                                                      |
             * ::: delegatecall to implementation ::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 36          | CALLDATASIZE   | cds 0 0             | [0..calldatasize): calldata     |
             * 3d          | RETURNDATASIZE | 0 cds 0 0           | [0..calldatasize): calldata     |
             * 7f slot     | PUSH32 slot    | s 0 cds 0 0         | [0..calldatasize): calldata     |
             * 54          | SLOAD          | i cds 0 0           | [0..calldatasize): calldata     |
             * 5a          | GAS            | g i cds 0 0         | [0..calldatasize): calldata     |
             * f4          | DELEGATECALL   | succ                | [0..calldatasize): calldata     |
             *                                                                                      |
             * ::: copy returndata to memory :::::::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 3d          | RETURNDATASIZE | rds succ            | [0..calldatasize): calldata     |
             * 60 0x00     | PUSH1 0x00     | 0 rds succ          | [0..calldatasize): calldata     |
             * 80          | DUP1           | 0 0 rds succ        | [0..calldatasize): calldata     |
             * 3e          | RETURNDATACOPY | succ                | [0..returndatasize): returndata |
             *                                                                                      |
             * ::: branch on delegatecall status :::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 60 dest     | PUSH1 dest     | dest succ           | [0..returndatasize): returndata |
             * 57          | JUMPI          |                     | [0..returndatasize): returndata |
             *                                                                                      |
             * ::: delegatecall failed, revert :::::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 3d          | RETURNDATASIZE | rds                 | [0..returndatasize): returndata |
             * 60 0x00     | PUSH1 0x00     | 0 rds               | [0..returndatasize): returndata |
             * fd          | REVERT         |                     | [0..returndatasize): returndata |
             *                                                                                      |
             * ::: delegatecall succeeded, return ::::::::::::::::::::::::::::::::::::::::::::::::: |
             * 5b          | JUMPDEST       |                     | [0..returndatasize): returndata |
             * 3d          | RETURNDATASIZE | rds                 | [0..returndatasize): returndata |
             * 60 0x00     | PUSH1 0x00     | 0 rds               | [0..returndatasize): returndata |
             * f3          | RETURN         |                     | [0..returndatasize): returndata |
             */
