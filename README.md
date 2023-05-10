# Kernel

## Modular smart contract

Adding new feature will be same as adding a new facet for erc2535 diamond standard.

For example, if you want to add a erc721 transfer feature, you can add a new facet for erc721 transfer feature.

And all those features has it's own validation logic, which has to be done through `validateUserOp` function

this validation logic can be set by the user, and it can be changed by user

So essentially, there will be
1. validation module per function
2. diamond facet for implementing the function

## Things to consider for implementing the validation module

In Kernel, validation module is called with `call` not `delegatecall`, which means that the validation module can not change the state of the Kernel itself.

But, this does comes with some limitation, **STORAGE ACCESS RULE**. Since erc4337 does not allow the userOp validation to access any storage outside of the account except the storage slot is related to the account address. So, if you are developing the Kernel validation module, you have to set the storage to not access any storage that violates the rule.