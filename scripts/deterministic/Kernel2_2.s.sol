pragma solidity ^0.8.0;
import "./DeterministicDeploy.s.sol";

library Kernel_2_2_Deploy {
    address constant EXPECTED_KERNEL_2_2_ADDRESS = 0x0DA6a956B9488eD4dd761E59f52FDc6c8068E6B5;
    bytes constant KERNEL_2_2_CODE = hex"000000000000000000000000000000000000000000000000000000000000000061014034620001b757601f620021e238819003918201601f19168301916001600160401b03831184841017620001bc57808492602094604052833981010312620001b757516001600160a01b0381168103620001b757306080524660a05260a062000069620001d2565b600681526005602082016512d95c9b995b60d21b815260206200008b620001d2565b838152019264181719171960d91b845251902091208160c0528060e052604051917f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f83526020830152604082015246606082015230608082015220906101009182526101209081527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd96a010000000000000000000080600160f01b031982541617905560405190611fef9283620001f3843960805183611a6a015260a05183611a8d015260c05183611aff015260e05183611b2501525182611a490152518181816104db0152818161079a015281816108a701528181610a3201528181610b5a01528181610d5401528181610e7501528181610f740152818161109e01528181611147015261148e0152f35b600080fd5b634e487b7160e01b600052604160045260246000fd5b60408051919082016001600160401b03811183821017620001bc5760405256fe6080604052600436101561001d575b366110815761001b611ece565b005b60003560e01c806306fdde031461018d5780630b3dc35414610188578063150b7a02146101835780631626ba7e1461017e57806329f8b17414610179578063333daf921461017457806334fcd5be1461016f5780633659cfe61461016a5780633a871cdd146101655780633e1b08121461016057806351166ba01461015b578063519454471461015657806354fd4d501461015157806355b14f501461014c57806357b750471461014757806384b0196e1461014257806388e7fd061461013d578063b0d691fe14610138578063bc197c8114610133578063d087d2881461012e578063d1f5789414610129578063d5416221146101245763f23a6e610361000e57610fef565b610f5d565b610ec1565b610e42565b610db3565b610d3e565b610d09565b610c61565b610c2a565b610b44565b610af0565b6109eb565b610922565b61085e565b61081c565b610776565b610693565b61060e565b610466565b610413565b610386565b610307565b6102d3565b600091031261019d57565b600080fd5b634e487b7160e01b600052604160045260246000fd5b6001600160401b0381116101cb57604052565b6101a2565b606081019081106001600160401b038211176101cb57604052565b608081019081106001600160401b038211176101cb57604052565b604081019081106001600160401b038211176101cb57604052565b90601f801991011681019081106001600160401b038211176101cb57604052565b6040519061024f826101eb565b565b6040519061016082018281106001600160401b038211176101cb57604052565b6040519061027e82610206565b600682526512d95c9b995b60d21b6020830152565b919082519283825260005b8481106102bf575050826000602080949584010152601f8019910116010190565b60208183018101518483018201520161029e565b3461019d57600036600319011261019d576103036102ef610271565b604051918291602083526020830190610293565b0390f35b3461019d57600036600319011261019d576020600080516020611fcf8339815191525460501c6040519060018060a01b03168152f35b6001600160a01b0381160361019d57565b359061024f8261033d565b9181601f8401121561019d578235916001600160401b03831161019d576020838186019501011161019d57565b3461019d57608036600319011261019d576103a260043561033d565b6103ad60243561033d565b6064356001600160401b03811161019d576103cc903690600401610359565b5050604051630a85bd0160e11b8152602090f35b90604060031983011261019d5760043591602435906001600160401b03821161019d5761040f91600401610359565b9091565b3461019d57602061042c610426366103e0565b91611b5b565b6040516001600160e01b03199091168152f35b600435906001600160e01b03198216820361019d57565b65ffffffffffff81160361019d57565b60c036600319011261019d5761047a61043f565b602435906104878261033d565b604435906104948261033d565b6064356104a081610456565b608435936104ad85610456565b60a4356001600160401b03811161019d576104cc903690600401610359565b9590946001600160a01b0393337f00000000000000000000000000000000000000000000000000000000000000008616141580610604575b6105f25784926105396105659261052a61051c610242565b65ffffffffffff9094168452565b65ffffffffffff166020830152565b6001600160a01b03851660408201526001600160a01b038316606082015261056087611049565b61172b565b1693843b1561019d576040519063064acaab60e11b8252818061058f6000998a94600484016117de565b038183895af180156105ed576105d4575b5016906001600160e01b0319167fed03d2572564284398470d3f266a693e29ddfff3eba45fc06c5e91013d3213538480a480f35b806105e16105e7926101b8565b80610192565b386105a0565b611475565b604051637046c88d60e01b8152600490fd5b5030331415610504565b3461019d576020610627610621366103e0565b91611e13565b604051908152f35b9291926001600160401b0382116101cb5760405191610658601f8201601f191660200184610221565b82948184528183011161019d578281602093846000960137010152565b9080601f8301121561019d578160206106909335910161062f565b90565b60208060031936011261019d576001600160401b0360043581811161019d573660238201121561019d578060040135918083116101cb578260051b906040908151946106e187850187610221565b855285850191602480948601019436861161019d57848101935b86851061070b5761001b88611144565b843584811161019d5782016060602319823603011261019d57835191610730836101d0565b8782013561073d8161033d565b835260448201358b84015260648201359286841161019d576107678c94938a869536920101610675565b868201528152019401936106fb565b602036600319011261019d5760043561078e8161033d565b6001600160a01b0390337f00000000000000000000000000000000000000000000000000000000000000008316141580610812575b6105f257807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55167fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a2005b50303314156107c3565b60031960603682011261019d57600435906001600160401b03821161019d5761016090823603011261019d576106276020916044359060243590600401611481565b3461019d57602036600319011261019d576004356001600160c01b0381169081900361019d57604051631aab3f0d60e11b815230600482015260248101919091526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa80156105ed57610303916000916108f4575b506040519081529081906020820190565b610915915060203d811161091b575b61090d8183610221565b810190611396565b386108e3565b503d610903565b3461019d57602036600319011261019d5761030361096761094161043f565b60006060604051610951816101eb565b8281528260208201528260408201520152611049565b60405190610974826101eb565b805465ffffffffffff80821684528160301c16602084015260601c60408301526001808060a01b03910154166060820152604051918291829190916060608082019365ffffffffffff80825116845260208201511660208401528160018060a01b0391826040820151166040860152015116910152565b608036600319011261019d57600435610a038161033d565b6044356001600160401b03811161019d57610a22903690600401610675565b90606435600281101561019d57337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316141580610ac5575b80610ab0575b6105f257610a75816110fa565b610a9e576000828193926020839451920190602435905af13d82803e15610a9a573d90f35b3d90fd5b6040516367ce775960e01b8152600490fd5b50610ac0610abc611c13565b1590565b610a68565b5030331415610a62565b60405190610adc82610206565b6005825264181719171960d91b6020830152565b3461019d57600036600319011261019d576103036102ef610acf565b90604060031983011261019d57600435610b258161033d565b91602435906001600160401b03821161019d5761040f91600401610359565b610b4d36610b0c565b90916001600160a01b03337f00000000000000000000000000000000000000000000000000000000000000008216141580610c20575b6105f25780600080516020611fcf8339815191525460501c1691610ba681611eff565b1692836040519360009586947fa35f5cdc5fbabb614b4cd5064ce5543f43dc8fab0e4da41255230eb8aba2531c8680a3813b15610c1c578385610bfa819593829463064acaab60e11b8452600484016117de565b03925af180156105ed57610c0c575080f35b806105e1610c19926101b8565b80f35b8380fd5b5030331415610b83565b3461019d57600036600319011261019d576020600080516020611fcf8339815191525460e01b6040519063ffffffff60e01b168152f35b3461019d57600036600319011261019d57610cb7610c7d610271565b610c85610acf565b90604051928392600f60f81b8452610ca960209360e08587015260e0860190610293565b908482036040860152610293565b90466060840152306080840152600060a084015282820360c08401528060605192838152019160809160005b828110610cf257505050500390f35b835185528695509381019392810192600101610ce3565b3461019d57600036600319011261019d576020600080516020611fcf8339815191525465ffffffffffff60405191831c168152f35b3461019d57600036600319011261019d576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b9181601f8401121561019d578235916001600160401b03831161019d576020808501948460051b01011161019d57565b3461019d5760a036600319011261019d57610dcf60043561033d565b610dda60243561033d565b6001600160401b0360443581811161019d57610dfa903690600401610d83565b505060643581811161019d57610e14903690600401610d83565b505060843590811161019d57610e2e903690600401610359565b505060405163bc197c8160e01b8152602090f35b3461019d57600036600319011261019d57604051631aab3f0d60e11b8152306004820152600060248201526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa80156105ed57610303916000916108f457506040519081529081906020820190565b610eca36610b0c565b600080516020611fcf83398151915254919290916001600160a01b03919060501c8216610f4c57610efa81611eff565b1691823b1561019d57610f2f926000928360405180968195829463064acaab60e11b84526020600485015260248401916117bd565b03925af180156105ed57610f3f57005b806105e161001b926101b8565b60405162dc149f60e41b8152600490fd5b602036600319011261019d57610f7161043f565b337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316141580610fe5575b6105f257600080516020611fcf83398151915290815469ffffffffffff000000004260201b169160e01c9069ffffffffffffffffffff191617179055600080f35b5030331415610fa4565b3461019d5760a036600319011261019d5761100b60043561033d565b61101660243561033d565b6084356001600160401b03811161019d57611035903690600401610359565b505060405163f23a6e6160e01b8152602090f35b63ffffffff60e01b166000527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dda602052604060002090565b600061109781356001600160e01b031916611049565b5460601c337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03161415806110eb575b6105f257818091368280378136915af43d82803e15610a9a573d90f35b506110f4611c13565b156110ce565b6002111561110457565b634e487b7160e01b600052602160045260246000fd5b805182101561112e5760209160051b010190565b634e487b7160e01b600052603260045260246000fd5b337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03161415806111d1575b6105f25780519060005b82811061118d57505050565b60008061119a838561111a565b5180516001600160a01b03166020916040838201519101519283519301915af13d6000803e156111cc57600101611181565b3d6000fd5b506111dd610abc611c13565b611177565b9060041161019d5790600490565b909291928360041161019d57831161019d57600401916003190190565b9060241161019d5760100190601490565b9060581161019d5760380190602090565b9060241161019d5760040190602090565b9060381161019d5760240190601490565b90600a1161019d5760040190600690565b9060101161019d57600a0190600690565b9093929384831161019d57841161019d578101920390565b6001600160e01b031990358181169392600481106112a857505050565b60040360031b82901b16169150565b91906101608382031261019d576112cc610251565b926112d68161034e565b8452602081013560208501526040810135916001600160401b039283811161019d5781611304918401610675565b6040860152606082013583811161019d5781611321918401610675565b60608601526080820135608086015260a082013560a086015260c082013560c086015260e082013560e086015261010080830135908601526101208083013584811161019d5782611373918501610675565b90860152610140928383013590811161019d576113909201610675565b90830152565b9081602091031261019d575190565b606080825282516001600160a01b0316908201529193929160409161146b9060208101516080840152838101516113ea610160918260a08701526101c0860190610293565b9061145861140a606085015193605f1994858983030160c08a0152610293565b608085015160e088015260a085015192610100938489015260c08601519061012091828a015260e08701519461014095868b0152870151908901528501518488830301610180890152610293565b92015190848303016101a0850152610293565b9460208201520152565b6040513d6000823e3d90fd5b6001600160a01b039392917f00000000000000000000000000000000000000000000000000000000000000008516330361169f576004948535928361014481013501918760248401930135946114e06114da87866111e2565b9061128b565b926001600160e01b031980851691821561167c576114ff9036906112b7565b94611519600080516020611fcf8339815191525460e01b90565b1616156115315760405163fc2f51c560e01b81528a90fd5b97989697600160e01b810361162b575090602095966115bb61158961157061156b6114da87606460009901350160248782013591016111e2565b611049565b6001810154909a9081906001600160a01b0316986111f0565b995460d081901b6001600160d01b03191660709190911b65ffffffffffff60a01b1617995b8b61161d575b369161062f565b6101408501526115df604051998a9788968794633a871cdd60e01b865285016113a5565b0393165af19081156105ed57610690926000926115fd575b50611f4c565b61161691925060203d811161091b5761090d8183610221565b90386115f7565b348080808f335af1506115b4565b9095939190600160e11b0361166f576116656115bb946000936116606114da8a606460209c01350160248d82013591016111e2565b6117ef565b91999296916115ae565b5050505050505050600190565b9697505050505050506106909394508215611d47573434343486335af150611d47565b604051636b31ba1560e11b8152600490fd5b6bffffffffffffffffffffffff1990358181169392601481106116d357505050565b60140360031b82901b16169150565b3590602081106116f0575090565b6000199060200360031b1b1690565b6001600160d01b0319903581811693926006811061171c57505050565b60060360031b82901b16169150565b81516020830151604084015160309190911b6bffffffffffff0000000000001665ffffffffffff9290921691909117606091821b6bffffffffffffffffffffffff19161782559091015160019190910180546001600160a01b0319166001600160a01b0392909216919091179055565b90602091808252806000848401376000828201840152601f01601f1916010190565b908060209392818452848401376000828201840152601f01601f1916010190565b9160206106909381815201916117bd565b91906117fb828261120d565b611804916116b1565b60601c93611812838361121e565b61181b916116e2565b605883016078820194858360580190611835918388611273565b61183e916116e2565b611848828761122f565b611851916116e2565b61185b8388611240565b611864916116b1565b60601c61187236878761062f565b8051602091820120604080517f3ce406685c1b3551d706d85a68afdaa49ac4e07b451ad9b8ff8b58c3ee9641769381019384526001600160e01b03198e169181019190915260608101949094526001600160a01b0392909216608084015260a080840192909252908252906118e860c082610221565b5190206118f490611a47565b9084019660788801611907918489611273565b9061191192611e13565b61191b828761122f565b6001600160a01b03199161192f91906116e2565b1661193991611f4c565b9660788688010196820360771901956119528382611251565b61195b916116ff565b60d01c926119698183611262565b611972916116ff565b60d01c916119808282611240565b611989916116b1565b60601c916119969161120d565b61199f916116b1565b60601c916119ab610242565b65ffffffffffff909516855265ffffffffffff1660208501526001600160a01b031660408401526001600160a01b031660608301526119e990611049565b906119f39161172b565b6001600160a01b03871691823b1561019d57611a29926000928360405180968195829463064acaab60e11b8452600484016117de565b03925af180156105ed57611a3a5750565b806105e161024f926101b8565b7f00000000000000000000000000000000000000000000000000000000000000007f000000000000000000000000000000000000000000000000000000000000000030147f000000000000000000000000000000000000000000000000000000000000000046141615611ad4575b671901000000000000600052601a52603a526042601820906000603a52565b5060a06040517f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f81527f000000000000000000000000000000000000000000000000000000000000000060208201527f0000000000000000000000000000000000000000000000000000000000000000604082015246606082015230608082015220611ab5565b90611b669291611e13565b65ffffffffffff808260a01c16908115600114611bd1575b428360d01c11611bc15742911610611bb4576001600160a01b0316611ba857630b135d3f60e11b90565b6001600160e01b031990565b506001600160e01b031990565b506001600160e01b031992915050565b905080611b7e565b9081602091031261019d5751801515810361019d5790565b6001600160a01b0390911681526040602082018190526106909291019061179b565b611c1d3633611e7b565b611d4257611c366000356001600160e01b031916611049565b6001810154611c55906001600160a01b03165b6001600160a01b031690565b906001600160a01b03821615908115611d06575b8115611cdb575b5015611c7c5750600090565b60206040518092639ea9bd5960e01b82528180611c9d363360048401611bf1565b03915afa9081156105ed57600091611cb3575090565b610690915060203d8111611cd4575b611ccc8183610221565b810190611bd9565b503d611cc2565b54611cf5915065ffffffffffff165b65ffffffffffff1690565b65ffffffffffff4291161138611c70565b905065ffffffffffff611d26611cea835465ffffffffffff9060301c1690565b168015159081611d38575b5090611c69565b9050421138611d31565b600190565b9091611d5336836112b7565b610140928381013590601e198136030182121561019d5701938435946001600160401b03861161019d5760200193853603851361019d57611d9d6115b487611de5986020986111f0565b908301526000611dc7611c49600080516020611fcf8339815191525460501c60018060a01b031690565b9260405196879586948593633a871cdd60e01b8552600485016113a5565b03925af19081156105ed57600091611dfb575090565b610690915060203d811161091b5761090d8183610221565b600080516020611fcf833981519152546040805163199ed7c960e11b8152600481019390935260248301529092602092849260501c6001600160a01b03169183918291611e65916044840191906117bd565b03915afa9081156105ed57600091611dfb575090565b600080516020611fcf8339815191525460408051639ea9bd5960e01b81526001600160a01b039384166004820152602481019190915292602092849260501c169082908190611c9d90604483019061179b565b7f88a5966d370b9919b20f3e2c13ff65706f196a4e32cc2c12bf57088f8852587460408051338152346020820152a1565b600080516020611fcf83398151915280547fffff0000000000000000000000000000000000000000ffffffffffffffffffff1660509290921b600160501b600160f01b0316919091179055565b8082186001600160a01b031615600114611f67575050600190565b65ffffffffffff60a01b8181169265ffffffffffff60a01b1992831692811691908415611fc5575b81168015611fbe575b848110908518028085189414611fb6575b5081811190821802181790565b925038611fa9565b5080611f98565b93508093611f8f56fe439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd90000000000000000000000005ff137d4b0fdcd49dca30c7cf57e578a026d2789";
    address constant EXPECTED_KERNEL_LITE_2_2_ADDRESS = 0xbEdb61Be086F3f15eE911Cc9AB3EEa945DEbFa96;
    bytes constant KERNEL_LITE_2_2_CODE = hex"0000000000000000000000000000000000000000000000000000000000000000610160346200021357601f6200230b38819003918201601f19168301916001600160401b0383118484101762000218578084926040948552833981010312620002135780516001600160a01b039182821682036200021357602001519182168092036200021357306080524660a05260a06200007a6200022e565b600681526005602082016512d95c9b995b60d21b815260206200009c6200022e565b838152019264181719171960d91b845251902091208160c0528060e052604051917f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f83526020830152604082015246606082015230608082015220916101009283526101209182527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd96a010000000000000000000080600160f01b03198254161790556101409081527fdea7fea882fba743201b2aeb1babf326b8944488db560784858525d123ee7e976001808060a01b0319825416179055604051916120bc93846200024f853960805184611b7c015260a05184611b9f015260c05184611c11015260e05184611c3701525183611b5b0152518281816104fb015281816107ba015281816108c701528181610a5201528181610b7301528181610d1201528181610e780152818161101c01528181611114015281816111c40152818161126d01526115c2015251818181610e160152610ed90152f35b600080fd5b634e487b7160e01b600052604160045260246000fd5b60408051919082016001600160401b03811183821017620002185760405256fe6080604052600436101561001d575b366111a75761001b611e6b565b005b60003560e01c806306fdde03146101ad5780630b3dc354146101a8578063150b7a02146101a35780631626ba7e1461019e57806329f8b17414610199578063333daf921461019457806334fcd5be1461018f5780633659cfe61461018a5780633a871cdd146101855780633e1b08121461018057806351166ba01461017b578063519454471461017657806354fd4d501461017157806355b14f501461016c57806357b750471461016757806384b0196e1461016257806388e7fd061461015d578063b0d691fe14610158578063bc197c8114610153578063cdaea3ed1461014e578063d087d28814610149578063d1f5789414610144578063d54162211461013f578063f23a6e611461013a5763f2fde38b0361000e576110f1565b611097565b611005565b610ec4565b610e45565b610e00565b610d71565b610cfc565b610cc7565b610c1f565b610be8565b610b64565b610b10565b610a0b565b610942565b61087e565b61083c565b610796565b6106b3565b61062e565b610486565b610433565b6103a6565b610327565b6102f3565b60009103126101bd57565b600080fd5b634e487b7160e01b600052604160045260246000fd5b6001600160401b0381116101eb57604052565b6101c2565b606081019081106001600160401b038211176101eb57604052565b608081019081106001600160401b038211176101eb57604052565b604081019081106001600160401b038211176101eb57604052565b90601f801991011681019081106001600160401b038211176101eb57604052565b6040519061026f8261020b565b565b6040519061016082018281106001600160401b038211176101eb57604052565b6040519061029e82610226565b600682526512d95c9b995b60d21b6020830152565b919082519283825260005b8481106102df575050826000602080949584010152601f8019910116010190565b6020818301810151848301820152016102be565b346101bd5760003660031901126101bd5761032361030f610291565b6040519182916020835260208301906102b3565b0390f35b346101bd5760003660031901126101bd57602060008051602061207c8339815191525460501c6040519060018060a01b03168152f35b6001600160a01b038116036101bd57565b359061026f8261035d565b9181601f840112156101bd578235916001600160401b0383116101bd57602083818601950101116101bd57565b346101bd5760803660031901126101bd576103c260043561035d565b6103cd60243561035d565b6064356001600160401b0381116101bd576103ec903690600401610379565b5050604051630a85bd0160e11b8152602090f35b9060406003198301126101bd5760043591602435906001600160401b0382116101bd5761042f91600401610379565b9091565b346101bd57602061044c61044636610400565b91611c6d565b6040516001600160e01b03199091168152f35b600435906001600160e01b0319821682036101bd57565b65ffffffffffff8116036101bd57565b60c03660031901126101bd5761049a61045f565b602435906104a78261035d565b604435906104b48261035d565b6064356104c081610476565b608435936104cd85610476565b60a4356001600160401b0381116101bd576104ec903690600401610379565b9590946001600160a01b0393337f00000000000000000000000000000000000000000000000000000000000000008616141580610624575b6106125784926105596105859261054a61053c610262565b65ffffffffffff9094168452565b65ffffffffffff166020830152565b6001600160a01b03851660408201526001600160a01b03831660608201526105808761116f565b611869565b1693843b156101bd576040519063064acaab60e11b825281806105af6000998a94600484016118d9565b038183895af1801561060d576105f4575b5016906001600160e01b0319167fed03d2572564284398470d3f266a693e29ddfff3eba45fc06c5e91013d3213538480a480f35b80610601610607926101d8565b806101b2565b386105c0565b6115a9565b604051637046c88d60e01b8152600490fd5b5030331415610524565b346101bd57602061064761064136610400565b91611f94565b604051908152f35b9291926001600160401b0382116101eb5760405191610678601f8201601f191660200184610241565b8294818452818301116101bd578281602093846000960137010152565b9080601f830112156101bd578160206106b09335910161064f565b90565b6020806003193601126101bd576001600160401b036004358181116101bd57366023820112156101bd578060040135918083116101eb578260051b9060409081519461070187850187610241565b85528585019160248094860101943686116101bd57848101935b86851061072b5761001b8861126a565b84358481116101bd578201606060231982360301126101bd57835191610750836101f0565b8782013561075d8161035d565b835260448201358b8401526064820135928684116101bd576107878c94938a869536920101610695565b8682015281520194019361071b565b60203660031901126101bd576004356107ae8161035d565b6001600160a01b0390337f00000000000000000000000000000000000000000000000000000000000000008316141580610832575b61061257807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55167fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b600080a2005b50303314156107e3565b6003196060368201126101bd57600435906001600160401b0382116101bd576101609082360301126101bd5761064760209160443590602435906004016115b5565b346101bd5760203660031901126101bd576004356001600160c01b038116908190036101bd57604051631aab3f0d60e11b815230600482015260248101919091526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa801561060d5761032391600091610914575b506040519081529081906020820190565b610935915060203d811161093b575b61092d8183610241565b8101906114ca565b38610903565b503d610923565b346101bd5760203660031901126101bd5761032361098761096161045f565b600060606040516109718161020b565b828152826020820152826040820152015261116f565b604051906109948261020b565b805465ffffffffffff80821684528160301c16602084015260601c60408301526001808060a01b03910154166060820152604051918291829190916060608082019365ffffffffffff80825116845260208201511660208401528160018060a01b0391826040820151166040860152015116910152565b60803660031901126101bd57600435610a238161035d565b6044356001600160401b0381116101bd57610a42903690600401610695565b9060643560028110156101bd57337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316141580610ae5575b80610ad0575b61061257610a9581611220565b610abe576000828193926020839451920190602435905af13d82803e15610aba573d90f35b3d90fd5b6040516367ce775960e01b8152600490fd5b50610ae0610adc611d3c565b1590565b610a88565b5030331415610a82565b60405190610afc82610226565b6005825264181719171960d91b6020830152565b346101bd5760003660031901126101bd5761032361030f610aef565b9060406003198301126101bd57600435610b458161035d565b91602435906001600160401b0382116101bd5761042f91600401610379565b610b6d36610b2c565b505050337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316141580610bde575b6106125760405162461bcd60e51b815260206004820152600f60248201526e1b9bdd081a5b5c1b195b595b9d1959608a1b6044820152606490fd5b5030331415610ba3565b346101bd5760003660031901126101bd57602060008051602061207c8339815191525460e01b6040519063ffffffff60e01b168152f35b346101bd5760003660031901126101bd57610c75610c3b610291565b610c43610aef565b90604051928392600f60f81b8452610c6760209360e08587015260e08601906102b3565b9084820360408601526102b3565b90466060840152306080840152600060a084015282820360c08401528060605192838152019160809160005b828110610cb057505050500390f35b835185528695509381019392810192600101610ca1565b346101bd5760003660031901126101bd57602060008051602061207c8339815191525465ffffffffffff60405191831c168152f35b346101bd5760003660031901126101bd576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b9181601f840112156101bd578235916001600160401b0383116101bd576020808501948460051b0101116101bd57565b346101bd5760a03660031901126101bd57610d8d60043561035d565b610d9860243561035d565b6001600160401b036044358181116101bd57610db8903690600401610d41565b50506064358181116101bd57610dd2903690600401610d41565b50506084359081116101bd57610dec903690600401610379565b505060405163bc197c8160e01b8152602090f35b346101bd5760003660031901126101bd576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b346101bd5760003660031901126101bd57604051631aab3f0d60e11b8152306004820152600060248201526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa801561060d576103239160009161091457506040519081529081906020820190565b610ecd36610b2c565b916001600160a01b03907f0000000000000000000000000000000000000000000000000000000000000000821690821603610fb55760008051602061209c8339815191525416610f6457610f30610f2a61001b93610f3693611308565b906117ef565b60601c90565b60008051602061209c83398151915280546001600160a01b0319166001600160a01b03909216919091179055565b60405162461bcd60e51b8152602060048201526024808201527f4b65726e656c4c69746545434453413a20616c726561647920696e697469616c6044820152631a5e995960e21b6064820152608490fd5b60405162461bcd60e51b815260206004820152602260248201527f4b65726e656c4c69746545434453413a20696e76616c69642076616c6964617460448201526137b960f11b6064820152608490fd5b60203660031901126101bd5761101961045f565b337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031614158061108d575b6106125760008051602061207c83398151915290815469ffffffffffff000000004260201b169160e01c9069ffffffffffffffffffff191617179055600080f35b503033141561104c565b346101bd5760a03660031901126101bd576110b360043561035d565b6110be60243561035d565b6084356001600160401b0381116101bd576110dd903690600401610379565b505060405163f23a6e6160e01b8152602090f35b60203660031901126101bd576004356111098161035d565b6001600160a01b03337f00000000000000000000000000000000000000000000000000000000000000008216141580611165575b6106125760008051602061209c83398151915280546001600160a01b03191691909216179055005b503033141561113d565b63ffffffff60e01b166000527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dda602052604060002090565b60006111bd81356001600160e01b03191661116f565b5460601c337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316141580611211575b61061257818091368280378136915af43d82803e15610aba573d90f35b5061121a611d3c565b156111f4565b6002111561122a57565b634e487b7160e01b600052602160045260246000fd5b80518210156112545760209160051b010190565b634e487b7160e01b600052603260045260246000fd5b337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03161415806112f7575b6106125780519060005b8281106112b357505050565b6000806112c08385611240565b5180516001600160a01b03166020916040838201519101519283519301915af13d6000803e156112f2576001016112a7565b3d6000fd5b50611303610adc611d3c565b61129d565b906014116101bd5790601490565b906004116101bd5790600490565b90929192836004116101bd5783116101bd57600401916003190190565b906024116101bd5760100190601490565b906058116101bd5760380190602090565b906024116101bd5760040190602090565b906038116101bd5760240190601490565b90600a116101bd5760040190600690565b906010116101bd57600a0190600690565b909392938483116101bd5784116101bd578101920390565b6001600160e01b031990358181169392600481106113dc57505050565b60040360031b82901b16169150565b9190610160838203126101bd57611400610271565b9261140a8161036e565b8452602081013560208501526040810135916001600160401b03928381116101bd5781611438918401610695565b604086015260608201358381116101bd5781611455918401610695565b60608601526080820135608086015260a082013560a086015260c082013560c086015260e082013560e08601526101008083013590860152610120808301358481116101bd57826114a7918501610695565b9086015261014092838301359081116101bd576114c49201610695565b90830152565b908160209103126101bd575190565b606080825282516001600160a01b0316908201529193929160409161159f90602081015160808401528381015161151e610160918260a08701526101c08601906102b3565b9061158c61153e606085015193605f1994858983030160c08a01526102b3565b608085015160e088015260a085015192610100938489015260c08601519061012091828a015260e08701519461014095868b01528701519089015285015184888303016101808901526102b3565b92015190848303016101a08501526102b3565b9460208201520152565b6040513d6000823e3d90fd5b6001600160a01b039392917f0000000000000000000000000000000000000000000000000000000000000000851633036117dd5760049485359283610144810135019187602484019301359461161461160e8786611316565b906113bf565b926001600160e01b03198085169182156117b0576116339036906113eb565b9461164d60008051602061207c8339815191525460e01b90565b1616156116655760405163fc2f51c560e01b81528a90fd5b97989697600160e01b810361175f575090602095966116ef6116bd6116a461169f61160e8760646000990135016024878201359101611316565b61116f565b6001810154909a9081906001600160a01b031698611324565b995460d081901b6001600160d01b03191660709190911b65ffffffffffff60a01b1617995b8b611751575b369161064f565b610140850152611713604051998a9788968794633a871cdd60e01b865285016114d9565b0393165af190811561060d576106b092600092611731575b50611ff9565b61174a91925060203d811161093b5761092d8183610241565b903861172b565b348080808f335af1506116e8565b9095939190600160e11b036117a3576117996116ef9460009361179461160e8a606460209c01350160248d8201359101611316565b611901565b91999296916116e2565b5050505050505050600190565b9750505050505050916106b0939450806117cb575b50611e9c565b3490349034903490335af150386117c5565b604051636b31ba1560e11b8152600490fd5b6bffffffffffffffffffffffff19903581811693926014811061181157505050565b60140360031b82901b16169150565b35906020811061182e575090565b6000199060200360031b1b1690565b6001600160d01b0319903581811693926006811061185a57505050565b60060360031b82901b16169150565b81516020830151604084015160309190911b6bffffffffffff0000000000001665ffffffffffff9290921691909117606091821b6bffffffffffffffffffffffff19161782559091015160019190910180546001600160a01b0319166001600160a01b0392909216919091179055565b90918060409360208452816020850152848401376000828201840152601f01601f1916010190565b919061190d8282611341565b611916916117ef565b60601c936119248383611352565b61192d91611820565b6058830160788201948583605801906119479183886113a7565b61195091611820565b61195a8287611363565b61196391611820565b61196d8388611374565b611976916117ef565b60601c61198436878761064f565b8051602091820120604080517f3ce406685c1b3551d706d85a68afdaa49ac4e07b451ad9b8ff8b58c3ee9641769381019384526001600160e01b03198e169181019190915260608101949094526001600160a01b0392909216608084015260a080840192909252908252906119fa60c082610241565b519020611a0690611b59565b9084019660788801611a199184896113a7565b90611a2392611f94565b611a2d8287611363565b6001600160a01b031991611a419190611820565b16611a4b91611ff9565b966078868801019682036077190195611a648382611385565b611a6d9161183d565b60d01c92611a7b8183611396565b611a849161183d565b60d01c91611a928282611374565b611a9b916117ef565b60601c91611aa891611341565b611ab1916117ef565b60601c91611abd610262565b65ffffffffffff909516855265ffffffffffff1660208501526001600160a01b031660408401526001600160a01b03166060830152611afb9061116f565b90611b0591611869565b6001600160a01b03871691823b156101bd57611b3b926000928360405180968195829463064acaab60e11b8452600484016118d9565b03925af1801561060d57611b4c5750565b8061060161026f926101d8565b7f00000000000000000000000000000000000000000000000000000000000000007f000000000000000000000000000000000000000000000000000000000000000030147f000000000000000000000000000000000000000000000000000000000000000046141615611be6575b671901000000000000600052601a52603a526042601820906000603a52565b5060a06040517f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f81527f000000000000000000000000000000000000000000000000000000000000000060208201527f0000000000000000000000000000000000000000000000000000000000000000604082015246606082015230608082015220611bc7565b90611c789291611f94565b65ffffffffffff808260a01c16908115600114611ce3575b428360d01c11611cd35742911610611cc6576001600160a01b0316611cba57630b135d3f60e11b90565b6001600160e01b031990565b506001600160e01b031990565b506001600160e01b031992915050565b905080611c90565b908160209103126101bd575180151581036101bd5790565b6001600160a01b0390911681526040602082018190528101829052606091806000848401376000828201840152601f01601f1916010190565b60008051602061209c833981519152546001600160a01b039081163314611e6557611d726000356001600160e01b03191661116f565b60018101546001600160a01b031691821615908115611e29575b8115611dfe575b5015611d9f5750600090565b60206040518092639ea9bd5960e01b82528180611dc0363360048401611d03565b03915afa90811561060d57600091611dd6575090565b6106b0915060203d8111611df7575b611def8183610241565b810190611ceb565b503d611de5565b54611e18915065ffffffffffff165b65ffffffffffff1690565b65ffffffffffff4291161138611d93565b905065ffffffffffff611e49611e0d835465ffffffffffff9060301c1690565b168015159081611e5b575b5090611d8c565b9050421138611e54565b50600190565b7f88a5966d370b9919b20f3e2c13ff65706f196a4e32cc2c12bf57088f8852587460408051338152346020820152a1565b90611ecc906020527b19457468657265756d205369676e6564204d6573736167653a0a3332600052603c60042090565b9061014081013590601e19813603018212156101bd5701908135916001600160401b0383116101bd576020019180360383136101bd576116e881611f1392611f1995611324565b90611f45565b60008051602061209c833981519152546001600160a01b03908116911603611f4057600090565b600190565b6001608060006041602094969596604080519880519285526060810151851a88528781015182520151606052145afa51913d15611f86576000606052604052565b638baa579f6000526004601cfd5b6020527b19457468657265756d205369676e6564204d6573736167653a0a3332600052603c600420611fcd9291611f139192369161064f565b60008051602061209c833981519152546001600160a01b03918216911614611ff457600190565b600090565b8082186001600160a01b031615600114612014575050600190565b65ffffffffffff60a01b8181169265ffffffffffff60a01b1992831692811691908415612072575b8116801561206b575b848110908518028085189414612063575b5081811190821802181790565b925038612056565b5080612045565b9350809361203c56fe439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd9dea7fea882fba743201b2aeb1babf326b8944488db560784858525d123ee7e970000000000000000000000005ff137d4b0fdcd49dca30c7cf57e578a026d2789000000000000000000000000d9ab5096a832b9ce79914329daee236f8eea0390";
    function deploy() internal returns(address, address) {
        DeterministicDeploy.checkDeploy("Kernel 2.2", EXPECTED_KERNEL_2_2_ADDRESS, KERNEL_2_2_CODE);
        DeterministicDeploy.checkDeploy("Kernel lite 2.2", EXPECTED_KERNEL_LITE_2_2_ADDRESS, KERNEL_LITE_2_2_CODE);
        return (EXPECTED_KERNEL_2_2_ADDRESS, EXPECTED_KERNEL_LITE_2_2_ADDRESS);
    }
}
