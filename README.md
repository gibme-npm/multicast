# @gibme/multicast

[![NPM](https://img.shields.io/npm/v/@gibme/multicast)](https://www.npmjs.com/package/@gibme/multicast)
[![CI](https://github.com/gibme-npm/multicast/actions/workflows/ci.yml/badge.svg)](https://github.com/gibme-npm/multicast/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/@gibme/multicast)](https://github.com/gibme-npm/multicast/blob/master/LICENSE)
[![Node](https://img.shields.io/node/v/@gibme/multicast)](https://www.npmjs.com/package/@gibme/multicast)

A cross-platform multicast/unicast UDP socket library for Node.js (>=22). It abstracts platform-specific details across Windows, Linux, and macOS for IPv4/IPv6 multicast group management, providing a unified EventEmitter-based interface.

## Documentation

Full TypeDoc API documentation: [https://gibme-npm.github.io/multicast](https://gibme-npm.github.io/multicast)

## Features

* IPv4 and IPv6 multicast group support
* Cross-platform: Windows, Linux, and macOS
* Async factory-based creation with full TypeScript types
* Multicast and unicast message sending
* Automatic multi-interface handling:
  * One shared multicast socket bound to `0.0.0.0` / `::` for group traffic
  * One dedicated unicast socket per network interface for reliable multi-interface send/receive
* Bind to all interfaces, a specific IP address, or a named interface (e.g. `eth0`)
* Configurable TTL and multicast loopback
* Partial-failure collection on send (`Promise.allSettled` semantics)
* `fromSelf` flag on received messages to identify self-originated traffic

## Installation

```bash
npm install @gibme/multicast
# or
yarn add @gibme/multicast
```

## Quick Start

```typescript
import { MulticastSocket } from '@gibme/multicast';

const socket = await MulticastSocket.create({
    port: 5959,
    multicastGroup: '224.0.0.251',
    loopback: true
});

socket.on('message', (message, local, remote, fromSelf) => {
    console.log({ message: message.toString(), local, remote, fromSelf });
});

const errors = await socket.send(Buffer.from('Hello World'));

if (errors.length > 0) {
    console.error('Send failed on some interfaces:', errors);
}

// when done
await socket.destroy();
```

## How It Works

When you create a `MulticastSocket`, the library sets up:

1. **One multicast socket** bound to `0.0.0.0` (IPv4) or `::` (IPv6), joined to the specified multicast group on every selected interface. This socket receives all group traffic.
2. **One unicast socket per network interface**, each bound to that interface's address. These handle outgoing sends so that each interface transmits independently.

When you call `send()`, the message goes out on **every** unicast socket (unless you specify `srcAddress`). If any individual interface fails, the error is collected and returned — the remaining interfaces still send successfully.

The socket type (`udp4` / `udp6`) is detected automatically from the `multicastGroup` address.

### RFC 6762 §11 (off-link defense)

This library applies both halves of RFC 6762 §11 to defend against off-link injection of multicast traffic (the threat motivates protocols like mDNS):

* **Outbound** (RFC 6762 §11 first paragraph, SHOULD): every underlying socket (the shared multicast socket and each per-interface unicast socket) is configured with `IP_MULTICAST_TTL = 255` and `IP_TTL = 255` at bind time. The library does not expose a runtime override — TTL is hardcoded to 255 by design, because the §11 verification on receivers depends on it being exactly 255.
* **Inbound** (RFC 6762 §11 second paragraph, MUST): received packets are filtered by source address unless `linkLocalOnly: false` is set. Dropped packets surface as the `'drop'` event with reason `'off-link'`.

Two important details on the inbound check:

* **Approximation, not literal.** RFC 6762 §11 specifies the canonical inbound check as `IP_TTL === 255` on the received packet. Node's `dgram.Socket` does not expose the received TTL (no `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` ancillary data), so the library uses a source-address subnet check as a no-native-deps interim. A source-address subnet check does not catch on-link-IP source spoofing the way a TTL check would, so this is genuinely weaker than literal §11. There is no plan to work around this — the dgram TTL gap is upstream.
* **§11 multicast-destination exemption.** Per §11 itself: "All responses received with a destination address in the IP header that is the mDNS IPv4 link-local multicast address 224.0.0.251 or the mDNS IPv6 link-local multicast address FF02::FB are necessarily deemed to have originated on the local link, regardless of source IP address." The library implements this exemption by skipping the source-subnet check on packets received via the shared multicast socket (the only socket joined to the group, and therefore the only socket that receives multicast-destination traffic). Packets received via a per-interface unicast socket — i.e. unicast-destination traffic — still receive the source-subnet check. The trade-off: the exemption permits the cross-subnet-overlay traffic that the spec explicitly addresses, but it relies on multicast routing/switching to keep off-link traffic out of the group. Hosts behind misconfigured multicast routers may receive off-link multicast that the (unavailable) IP_TTL=255 check would have caught.

Disable the inbound filter with `linkLocalOnly: false` if you need to receive multicast across routed segments deliberately (e.g. SSDP over Layer 3, multicast across VPN tunnels).

## API

### `MulticastSocket.create(options): Promise<MulticastSocket>`

Async factory that creates, binds, and returns a new socket.

#### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `port` | `number` | *(required)* | The local port to bind to. |
| `multicastGroup` | `string` | *(required)* | The multicast group address to join (e.g. `'224.0.0.251'`). |
| `host` | `string \| Address4 \| Address6` | all interfaces | The local address or interface name to bind to. If omitted, all available interfaces are used. When an IP address is provided, only the matching interface is used. When an interface name is provided (e.g. `'eth0'`), all addresses on that interface are used. |
| `loopback` | `boolean` | `false` | When `true`, the socket receives its own outgoing multicast packets via the `'message'` event (with `fromSelf` set to `true`). |
| `reuseAddr` | `boolean` | `true` | Enables `SO_REUSEADDR` on the socket. |
| `reusePort` | `boolean` | `false` | Enables `SO_REUSEPORT` on the socket (implicitly sets `exclusive` to `true`). |
| `exclusive` | `boolean` | `false` | When `true`, the socket handle is not shared with cluster workers. |
| `linkLocalOnly` | `boolean` | `true` | RFC 6762 §11 inbound origin verification. Drops received messages whose source address is not on a local-link subnet of any local interface (loopback is allowed). Dropped packets surface as the `'drop'` event. Set to `false` for receive scenarios that legitimately cross routed segments (e.g. SSDP over Layer 3). |

### `socket.send(message, options?): Promise<Error[]>`

Sends a message to the multicast group or a unicast destination. Returns an array of errors for any interfaces that failed (empty on full success). Partial failures do not prevent delivery on other interfaces.

#### Send Options

| Option | Type | Default | Description |
|---|---|---|---|
| `useMulticastSocket` | `boolean` | `false` | Send via the shared multicast socket instead of per-interface unicast sockets. |
| `srcAddress` | `string \| Address4 \| Address6` | all interfaces | Send from a specific interface only. |
| `dstAddress` | `string \| Address4 \| Address6` | `multicastGroup` | Override the destination address (e.g. for unicast replies). |
| `dstPort` | `number` | `port` | Override the destination port. |

### `socket.destroy(): Promise<void>`

Closes all underlying sockets, drops multicast group membership, and removes all event listeners from both the internal sockets and this instance. This is the recommended way to fully tear down a socket.

### `socket.close(): Promise<void>`

Closes all underlying sockets and drops multicast group membership but does **not** remove event listeners. Prefer `destroy()` for full cleanup.

### `socket.setMulticastLoopback(loopback: boolean): void`

Sets or clears the `IP_MULTICAST_LOOP` socket option at runtime.

### `socket.ref(): void`

Adds all underlying sockets back to the Node.js event loop reference count (the default). The process will not exit while the sockets are open.

### `socket.unref(): void`

Removes all underlying sockets from the Node.js event loop reference count, allowing the process to exit while the sockets are still open.

### Properties

| Property | Type | Description |
|---|---|---|
| `socket.addresses` | `string[]` | The resolved interface addresses (without CIDR prefix). |
| `socket.interfaces` | `(Address4 \| Address6)[]` | The resolved network interfaces as parsed IP address objects. |
| `socket.addressInfo` | `AddressInfo[]` | Address info for all underlying sockets (multicast + unicast). |
| `socket.options` | `MulticastSocket.Options` | The options used to create this socket. |

### Events

All events pass the `local: AddressInfo` of the socket that triggered them.

| Event | Arguments | Description |
|---|---|---|
| `message` | `(message: Buffer, local: AddressInfo, remote: RemoteInfo, fromSelf: boolean)` | A UDP message was received and passed all inbound filters. `fromSelf` indicates whether the message originated from this instance. |
| `drop` | `(message: Buffer, local: AddressInfo, remote: RemoteInfo, reason: 'off-link')` | A received UDP message was rejected by an inbound filter. Currently the only reason is `'off-link'` (failed the `linkLocalOnly` check). Useful for logging or alerting on suspect traffic. |
| `close` | `(local: AddressInfo)` | An underlying socket was closed. |
| `connect` | `(local: AddressInfo)` | An underlying socket connected. |
| `error` | `(error: Error, local?: AddressInfo)` | An underlying socket encountered an error. |

## Helper Exports

The library re-exports `Address4` and `Address6` from the [`ip-address`](https://www.npmjs.com/package/ip-address) package and provides utility functions:

```typescript
import {
    MulticastSocket,
    Address4,
    Address6
} from '@gibme/multicast';

import {
    detect_type,
    get_addresses,
    is_valid_ip,
    compare_IP_addresses
} from '@gibme/multicast/helpers';
```

| Function | Description |
|---|---|
| `detect_type(address)` | Returns `'udp4'` or `'udp6'` for the given IP address string or object. Throws on invalid input. |
| `get_addresses(type, name?)` | Returns all non-internal network addresses on the system matching the socket type, with CIDR prefixes. Optionally filter by interface name. |
| `is_valid_ip(address)` | Returns an `Address4` or `Address6` if valid, `undefined` otherwise. |
| `compare_IP_addresses(a, b)` | Numeric comparator for sorting IP addresses (usable with `Array.sort()`). |
| `is_on_local_link(remote, type)` | Returns `true` if `remote` is on a local-link subnet of an interface this host owns (or is a loopback / IPv6 link-local address). Used internally by the `linkLocalOnly` filter; exported so downstream packages can apply the same check on their own dgram paths. |

## Examples

### Listen on a specific interface

```typescript
const socket = await MulticastSocket.create({
    port: 5959,
    multicastGroup: '224.0.0.251',
    host: '192.168.1.100'
});
```

### Listen on a named interface

```typescript
const socket = await MulticastSocket.create({
    port: 5959,
    multicastGroup: '224.0.0.251',
    host: 'eth0'
});
```

### IPv6 multicast

```typescript
const socket = await MulticastSocket.create({
    port: 5959,
    multicastGroup: 'ff02::1',
    loopback: true
});
```

### Send to a specific unicast destination

```typescript
const errors = await socket.send(Buffer.from('Hello'), {
    dstAddress: '192.168.1.50',
    dstPort: 9000
});
```

### Send from a specific interface

```typescript
const errors = await socket.send(Buffer.from('Hello'), {
    srcAddress: '192.168.1.100'
});
```

### Error handling

```typescript
socket.on('error', (error, local) => {
    console.error(`Error on ${local?.address}:${local?.port}:`, error.message);
});

const errors = await socket.send(Buffer.from('Hello'));
for (const err of errors) {
    console.warn('Partial send failure:', err.message);
}
```

### Allow process to exit while socket is open

```typescript
socket.unref();
```

## License

MIT
