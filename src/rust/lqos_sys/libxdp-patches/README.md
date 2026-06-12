# libxdp-sys vendored-source patches (dawn)

## xdp-dispatcher-changes-pkt-data.patch — REQUIRED for kernel >= 6.13

Kernel 6.13 added a verifier check (`changes_pkt_data`) on freplace/EXT
program attach: an extension that modifies packet data may not replace a
target function that doesn't. libxdp's dispatcher stubs (`prog0..progN`)
are trivial returns → any packet-modifying member (dawn's `xdp_prog` via
`bpf_xdp_adjust_meta` at lqos_kern.c:184, the lighthouse marker via DSCP
rewrite) is rejected with:

    Extension program changes packet data, while original does not
    (xdp_program__attach → EINVAL -22, "dispatcher attach failed in all modes")

Upstream xdp-tools has NO equivalent fix as of v1.6.3-20-ge946950 (their own
tools don't modify packets; upstream LibreQoS uses raw attach — the libxdp
composition is a dawn feature). Worth filing upstream.

The patch adds a runtime no-op `bpf_xdp_adjust_meta(ctx, 0)` to each stub so
the verifier marks them `changes_pkt_data` — then both modifying and
non-modifying members attach. Proven live 2026-06-12 on Proxmox 9.1 /
kernel 6.17.2 (office PVE): full marker(prog0)+sampler(prog1)+lqosd(prog2)
dispatcher chain on to-vpp.

## How to apply (build-time, per workspace that links libxdp-sys)

libxdp-sys 0.2.4 vendors xdp-tools and regenerates `xdp-dispatcher.c` from
`xdp-dispatcher.c.in` via m4 in its build.rs — so patching the template in a
crate copy is sufficient:

```sh
D=$(ls -d ~/.cargo/registry/src/*/libxdp-sys-0.2.4*)
cp -r "$D" /tmp/libxdp-sys-patched
python3 patch-dispatcher.py /tmp/libxdp-sys-patched/xdp-tools/lib/libxdp/xdp-dispatcher.c.in
# (or: patch -p1 -d /tmp/libxdp-sys-patched < xdp-dispatcher-changes-pkt-data.patch)
```

Then in the workspace root Cargo.toml:

```toml
[patch.crates-io]
libxdp-sys = { path = "/tmp/libxdp-sys-patched" }
```

**Applies to EVERY binary that attaches via the libxdp dispatcher** — each
statically embeds its own dispatcher object:
- lqosd (this repo, `cargo build --release -p lqosd`)
- lighthouse marker (ow-sdn: `cargo build --release -p marker --features ndpi`)
- (libreqos-agent links libxdp-sys but does not attach a dispatcher; rebuild
  not required as of 2026-06-12.)

CANONICALIZATION TODO (Neil): wire this into `lxc-services/scripts/build-lqosd.sh`
and the marker template build so fresh templates carry the fix; until then
6.13+ hosts need the runtime fallback `xdp_attach_mode = { mode = "raw" }`
(see dawn-sim canonical-baremetal-deploy.sh, which auto-selects).

## wrapper.c LQOSD_LIBBPF_DEBUG (committed alongside this)

`lqos_sys/src/bpf/wrapper.c`'s libbpf print hook silenced ALL libbpf output
including the kernel verifier log — which is why the rejection above was
invisible ("Invalid argument" with no why). It now forwards to stderr when
`LQOSD_LIBBPF_DEBUG=1` is set; default behavior unchanged.
