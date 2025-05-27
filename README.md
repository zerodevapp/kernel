# how to run coverage 

```sh
forge coverage --no-match-coverage "(script|test|Foo|Bar|validator|sdk|signer)" --report lcov && genhtml lcov.info --output-directory coverage --ignore-errors inconsistent --ignore-errors corrupt
```

and 
```sh
open coverage/index.html
```

## TODO
- Testing
    - [ ] certora testing
    - [ ] unit test coverage 100%
    - [ ] halmos testing

## Kernel V4
- [x] native v0.8 support
    - [x] factory update, needs to consider 7702 context
    - [x] eip712 userOpHash support
- [ ] native 7702 support
    - test
- [x] 7579 account
    - [x] erc7821 execute interface
    - [x] execute with signature
- [x] enable mode
    - [x] allow installing modules
    - [x] allow multichain replay signature
- [x] permission validation method
- [x] signature replay
    - [x] multichain replay
- [x] install with signature
