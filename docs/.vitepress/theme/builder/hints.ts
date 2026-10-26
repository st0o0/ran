import type { BuilderState, Hint, Register } from './types'
import { effectiveEnv, findTrap } from './state'
import { trapAddrs } from './addrs'

export const WIDE_PORT_SET = 20

/** Advice that is not an error or warning. The checks themselves come from the Go code (checker.ts). */
export function hints(reg: Register, state: BuilderState): Hint[] {
  const env = effectiveEnv(state)
  const out: Hint[] = []
  const udp = state.traps.filter((t) => findTrap(reg, t)?.transport === 'UDP')
  if (udp.length > 0) {
    out.push({
      id: 'udp-log-only',
      message: `${udp.join(', ')} (UDP) log and count only and never alert, because UDP source addresses can be spoofed. Expect more log lines than alerts; RAN_UDP_RATE_* limit the volume.`
    })
  }
  let ports = 0
  for (const t of state.traps) ports += trapAddrs(reg, env, t).length
  if (ports >= WIDE_PORT_SET) {
    out.push({
      id: 'wide-port-set',
      message: `${ports} listen ports are configured. A wide port set raises log volume and the number of exposed ports; consider RAN_PROBE_SUMMARY_WINDOW and RAN_MAX_SESSIONS.`
    })
  }
  if (state.traps.includes('catchall') || state.traps.includes('banner')) {
    out.push({
      id: 'catchall-volume',
      message: 'catchall and banner listen on operator-chosen ports and see unfiltered scan traffic; keep the port set small and watch the log volume.'
    })
  }
  if ((env.RAN_PROXY_TRUSTED ?? '').trim() === 'any') {
    out.push({
      id: 'trusted-any',
      message: 'RAN_PROXY_TRUSTED=any lets every peer send a PROXY header and so spoof the client address. Use a narrow list plus a firewall.'
    })
  }
  return out
}
