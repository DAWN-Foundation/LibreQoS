#!/usr/bin/env python3
"""Patch libxdp's xdp-dispatcher.c.in: mark the progN stubs as changing
packet data (no-op bpf_xdp_adjust_meta(ctx, 0)) so kernel >=6.13's
changes_pkt_data verifier check allows freplace by packet-modifying
extension programs (dawn lqosd xdp_prog + lighthouse marker).
Upstream xdp-tools has no equivalent fix as of v1.6.3-20."""
import sys

p = sys.argv[1]
s = open(p).read()

old = """forloop(`i', `0', NUM_PROGS,
`__attribute__ ((noinline))
int format(`prog%d', i)(struct xdp_md *ctx) {
        volatile int ret = XDP_DISPATCHER_RETVAL;

        if (!ctx)
          return XDP_ABORTED;
        return ret;
}
')"""

new = """forloop(`i', `0', NUM_PROGS,
`__attribute__ ((noinline))
int format(`prog%d', i)(struct xdp_md *ctx) {
        volatile int ret = XDP_DISPATCHER_RETVAL;

        if (!ctx)
          return XDP_ABORTED;
        /* dawn: mark stub as changes_pkt_data (runtime no-op) so kernel
         * >=6.13 allows freplace by extensions that modify packet data.
         * Without this the verifier rejects with: "Extension program
         * changes packet data, while original does not". */
        volatile int adj = bpf_xdp_adjust_meta(ctx, 0);
        (void)adj;
        return ret;
}
')"""

if old not in s:
    i = s.find("forloop")
    print("PATTERN NOT FOUND — stub region follows:")
    print(s[i:i + 500])
    sys.exit(1)

open(p, "w").write(s.replace(old, new, 1))
print("PATCHED OK:", p)
