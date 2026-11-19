// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { expectTypeOf, it } from 'vitest'
import type { DstackClientV0 } from '../index'

it('types the v0 TDX registers as null on non-TDX platforms', () => {
  type Tcb = Awaited<ReturnType<DstackClientV0['info']>>['tcb_info']
  type Register = 'mrtd' | 'rtmr0' | 'rtmr1' | 'rtmr2' | 'rtmr3'
  expectTypeOf<Pick<Tcb, Register>>().toEqualTypeOf<Record<Register, string | null>>()
})
