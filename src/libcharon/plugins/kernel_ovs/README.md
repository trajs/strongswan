# kernel-ovs: strongSwan IPsec backend for Open vSwitch's userspace datapath

`kernel-ovs` is a strongSwan plugin that installs the IPsec SAs negotiated by
charon in the `esp` tunnels of Open vSwitch's userspace datapath (OVS-DPDK,
AF_XDP), instead of in the Linux kernel.  The datapath threads of
`ovs-vswitchd` then encrypt and decrypt the traffic.

Like `kernel-netlink` (Linux) and `kernel-libipsec` (userspace), it
implements strongSwan's `kernel_ipsec_t` interface.  It talks to
`ovs-vswitchd` over its control socket, with the `esp/spi-alloc`,
`esp/sa-add`, `esp/sa-del`, `esp/sa-query` and `esp/sa-flush` commands.

## Requirements

- Open vSwitch with `esp` tunnel support and `options:esp_keying=ike`.
- strongSwan 5.9.13, the version this was built and tested with.  The plugin
  must be built against the source of the same version as the installed
  charon.

## Building and installing

In this source tree:

```
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --with-ipseclibdir=/usr/lib/ipsec \
    --disable-defaults --enable-charon --enable-swanctl --enable-kernel-netlink \
    --enable-kernel-ovs      # plus the plugins you need
make
sudo make install
```

The plugin must be built from the same version as the installed charon.  It is
listed before `kernel-netlink`, so it becomes the IPsec backend: charon uses the
first one that registers, and `kernel-netlink` still provides addresses and
routes.  With `charon.load_modular`, set `load = 10` in
`/etc/strongswan.d/charon/kernel-ovs.conf` for the same effect.  charon logs
`loaded plugins: ... kernel-ovs ...`.

## Configuration

Open vSwitch: an `esp` tunnel whose SAs come from IKE, bound to them by an
interface ID:

```
ovs-vsctl add-port br0 esp0 -- set Interface esp0 type=esp \
    options:remote_ip=192.168.25.2 options:esp_keying=ike options:esp_if_id=7
```

strongSwan (`swanctl.conf`): a CHILD_SA in tunnel mode with AES-GCM, with the
same interface ID:

```
children {
    ovs-esp {
        local_ts = 10.1.1.0/24
        remote_ts = 10.2.2.0/24
        mode = tunnel
        esp_proposals = aes256gcm16
        if_id_in = 7
        if_id_out = 7
    }
}
```

and, in `strongswan.conf`, since Open vSwitch's flow tables route the overlay:

```
charon {
    install_routes = no
}
```

`swanctl --list-sas` shows the packets and bytes counted by Open vSwitch, and
`ovs-appctl esp/show` the SAs installed in it.

Plugin options (`charon.plugins.kernel-ovs`):
`poll_interval` (5 s), `rundir` (`/var/run/openvswitch`) and `socket`.

### AppArmor

On Ubuntu, `/usr/sbin/charon-systemd` has an AppArmor profile, in complain mode
by default.  If it is enforced, allow the plugin to reach `ovs-vswitchd` in
`/etc/apparmor.d/local/usr.sbin.charon-systemd`:

```
/{,var/}run/openvswitch/ovs-vswitchd.pid r,
/{,var/}run/openvswitch/ovs-vswitchd.*.ctl rw,
```

## Behavior

- **Rekeying** does not disturb traffic.  A new outbound SA atomically replaces
  the previous one in Open vSwitch, without changing its datapath flows, and
  inbound SAs coexist until charon deletes the old one.
- **Lifetimes**: the plugin raises charon's expire events itself, from timers
  for time-based lifetimes, and from Open vSwitch's counters, polled every
  `poll_interval`, for byte- and packet-based ones.  A byte limit is therefore
  exceeded by up to `poll_interval` times the traffic rate, e.g. 3.5 GB at
  5.6 Gbit/s with the default.  Keep `life_bytes` well above `rekey_bytes`, or
  lower `poll_interval`.
- **ovs-vswitchd restarts**: the plugin notices within `poll_interval`,
  reinstalls the SAs and has charon rekey them, as their sequence numbers
  restart.
- **charon restarts**: charon keeps its SAs and keys only in memory, so nothing
  is reinstalled: new IKE and CHILD SAs must be negotiated, with `start_action`
  or `swanctl --initiate`.  A clean stop deletes the SAs in Open vSwitch, and
  packets are dropped until the new ones are installed.  After a crash, the old
  SAs keep forwarding traffic until charon starts again and the plugin removes
  them, with `esp/sa-flush`, as nothing else would rekey, expire or delete them.
  One charon must therefore own the IKE-keyed SAs of an ovs-vswitchd.
- **Policies** are not installed: Open vSwitch forwards according to its
  OpenFlow tables.

## Limitations

- ESP in tunnel mode with AES-GCM (16-byte ICV) only.
- `update_sa` is not supported, so MOBIKE address changes and NAT mapping
  changes are not followed.
- With UDP encapsulation in Open vSwitch (`esp_udp_encap`), IKE packets on the
  same port are dropped by the datapath, so IKE must not use port 4500 on that
  address.
- No usage time for SAs, so inactivity is detected from changes of the byte
  counters.

## License

GPL version 2 or later, like strongSwan, from which the plugin structure and
interfaces are derived.
