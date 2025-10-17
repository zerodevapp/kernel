import {
  createAccount,
  createAccountOwner,
  createAddress, decodeRevertReason,
  deployEntryPoint
} from './testutils'
import { fillSignAndPack } from './UserOp'
import { ethers } from 'hardhat'
import {
  EntryPoint,
  TestPaymasterWithPostOp,
  TestPaymasterWithPostOp__factory
} from '../typechain'
import { expect } from 'chai'
import { BaseContract } from 'ethers'
import { parseEther } from 'ethers/lib/utils'

describe('#postOp', () => {
  if (process.env.COVERAGE != null) {
    return
  }

  const ethersSigner = ethers.provider.getSigner()
  let entryPoint: EntryPoint

  const paymasters: TestPaymasterWithPostOp[] = []
  const lengths: number[] = [1, 31, 32, 33, 992, 993]

  before(async function () {
    entryPoint = await deployEntryPoint()

    for (const i of lengths) {
      const paymaster = await new TestPaymasterWithPostOp__factory(ethersSigner).deploy(entryPoint.address)
      const strlen = 2 + i * 2
      const context = '0x123456'.padEnd(strlen, 'abcdef').slice(0, strlen)
      await paymaster.setContext(context)
      paymasters.push(paymaster)
      await entryPoint.depositTo(paymaster.address, { value: parseEther('1') })
    }
  })

  const owner = createAccountOwner()
  it('should get context with single userop bundle', async () => {
    const { proxy: account } = await createAccount(ethersSigner, owner.address, entryPoint.address)
    const pm = paymasters[0]
    const op = await fillSignAndPack({
      sender: account.address,
      paymaster: pm.address,
      paymasterVerificationGasLimit: 50000,
      paymasterPostOpGasLimit: 10000

    }, owner, entryPoint)

    await entryPoint.handleOps([op], createAddress()).then(async r => r.wait())
    // console.log(parseLogs(rcpt.logs, pm, entryPoint))
    const postevent = await pm.queryFilter(pm.filters.PostOpActualGasCost())
    // console.log('postevent=', postevent)
    expect(postevent[0].args.isSame).to.be.true
  })

  it('should match contexts in a batch of many userops', async () => {
    const { proxy: account } = await createAccount(ethersSigner, owner.address, entryPoint.address)
    const ops = []
    let n = 0
    for (const pm of paymasters) {
      const op = await fillSignAndPack({
        sender: account.address,
        nonce: n++,
        paymaster: pm.address,
        paymasterVerificationGasLimit: 500000,
        paymasterPostOpGasLimit: 200000
      }, owner, entryPoint)
      ops.push(op)
    }
    const rcpt = await entryPoint.handleOps(ops, createAddress()).then(async r => r.wait())
      .catch(e => { throw new Error(decodeRevertReason(e)!) }) as any
    const events = parseLogs(rcpt.logs, paymasters[0], entryPoint)
    for (const ev of events) {
      // console.log('ev=', ev)
      if (ev.name === 'PostOpActualGasCost') {
        expect(ev.args.isSame).to.equal(true,
            `failed to pass context len ${ev.args.context.length as number} to postOp`)
      }
    }
  })
})

function parseLogs (logs: any[], ...contracts: BaseContract[]): any[] {
  return logs.map(e => {
    let saveex: any
    for (const c of contracts) {
      try {
        const parsed = c.interface.parseLog(e)
        return {
          name: parsed.name,
          args: parsed.args
        }
      } catch (ex) {
        saveex = ex
      }
    }
    throw saveex
  })
}
