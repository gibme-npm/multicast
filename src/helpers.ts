// Copyright (c) 2018-2025, Brandon Lehmann <brandonlehmann@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { SocketType } from 'dgram';
import { Address4, Address6 } from 'ip-address';
import { networkInterfaces } from 'os';

/**
 * Detects the UDP socket type based on the IP address supplied.
 *
 * @param address - an IPv4/IPv6 address as a string, {@link Address4}, or {@link Address6}
 * @returns `'udp4'` for IPv4 addresses, `'udp6'` for IPv6 addresses
 * @throws Error if the address string is not a valid IPv4 or IPv6 address
 */
export const detect_type = (address: Address4 | Address6 | string): SocketType => {
    if (typeof address === 'string') {
        if (Address4.isValid(address)) return 'udp4';
        if (Address6.isValid(address)) return 'udp6';

        throw new Error(`Invalid IP address: ${address}`);
    } else {
        if (address.v4) {
            return 'udp4';
        }

        return 'udp6';
    }
};

/**
 * Comparator for sorting IP addresses by their numeric value rather than
 * their string representation.
 *
 * Both addresses must be of the same family (both Address4 or both Address6).
 * Mixed-family input throws, because the underlying numeric ranges have no
 * meaningful total order across families.
 *
 * @param a - the first address to compare
 * @param b - the second address to compare
 * @returns `-1` if `a < b`, `0` if equal, `1` if `a > b`
 * @throws Error if `a` and `b` are not of the same address family
 */
export const compare_IP_addresses = (
    a: Address4 | Address6,
    b: Address4 | Address6
): -1 | 0 | 1 => {
    const aIsV4 = a instanceof Address4;
    const bIsV4 = b instanceof Address4;

    if (aIsV4 !== bIsV4) {
        throw new Error('compare_IP_addresses requires both addresses to be of the same family');
    }

    const diff = a.bigInt() - b.bigInt();

    return diff === BigInt(0) ? 0 : diff < BigInt(0) ? -1 : 1;
};

/**
 * Returns all non-internal network addresses on the system that match the
 * specified socket type, optionally filtered to a single network interface.
 *
 * Each returned address includes its CIDR prefix (e.g. `192.168.1.5/24`).
 *
 * @param type - `'udp4'` for IPv4 addresses, `'udp6'` for IPv6 addresses
 * @param name - if provided, only addresses from the named interface are returned
 * @returns an array of {@link Address4} or {@link Address6} instances
 */
export const get_addresses = (
    type: SocketType,
    name?: string
): (Address4 | Address6)[] => {
    const addresses: (Address4 | Address6)[] = [];

    const ifaces = networkInterfaces();

    if (name && !ifaces[name]) return [];

    for (const iface in ifaces) {
        if (!ifaces[iface]) continue;
        if (name && iface !== name) continue;

        for (const addr of ifaces[iface]) {
            if (addr.family === (type === 'udp4' ? 'IPv4' : 'IPv6') && !addr.internal) {
                if (!addr.cidr) {
                    throw new Error(
                        `Interface ${iface} address ${addr.address} is missing CIDR;` +
                        ' Node 22+ should always populate addr.cidr');
                }

                const address: Address4 | Address6 = type === 'udp4'
                    ? new Address4(addr.cidr)
                    : new Address6(addr.cidr);

                addresses.push(address);
            }
        }
    }

    // Dedup by the parsed address string. The previous `new Set(addresses)`
    // here was a no-op because Set uses reference equality and every parsed
    // Address4/Address6 above is a fresh instance.
    const dedup = new Map<string, Address4 | Address6>();
    for (const addr of addresses) {
        if (!dedup.has(addr.address)) dedup.set(addr.address, addr);
    }
    return [...dedup.values()];
};

/**
 * Parses the given string as an IPv4 or IPv6 address.
 *
 * @param address - the address string to validate
 * @returns an {@link Address4} or {@link Address6} instance if valid, or `undefined` if
 *          the string is not a valid IP address
 */
export const is_valid_ip = (address: string): Address4 | Address6 | undefined => {
    if (Address4.isValid(address)) return new Address4(address);
    if (Address6.isValid(address)) return new Address6(address);
};

const IPV4_LOOPBACK_SUBNET = new Address4('127.0.0.0/8');
const IPV6_LINK_LOCAL_SUBNET = new Address6('fe80::/10');
const IPV4_MULTICAST_SUBNET = new Address4('224.0.0.0/4');
const IPV6_MULTICAST_SUBNET = new Address6('ff00::/8');

/**
 * Returns `true` if `address` is in the multicast range for its family.
 *
 * - IPv4: `224.0.0.0/4` per RFC 5771 (and RFC 1112 §4 originally).
 * - IPv6: `ff00::/8` per RFC 4291 §2.7.
 *
 * Used to fail fast in `MulticastSocket.create` when the caller passes a
 * non-multicast address as `multicastGroup`, before any socket allocation.
 *
 * @param address - the address string to test
 * @param type - `'udp4'` or `'udp6'`
 * @returns `true` if the address is a syntactically valid multicast address
 */
export const is_multicast = (address: string, type: SocketType): boolean => {
    if (type === 'udp4') {
        if (!Address4.isValid(address)) return false;
        return new Address4(address).isInSubnet(IPV4_MULTICAST_SUBNET);
    }
    if (!Address6.isValid(address)) return false;
    return new Address6(address).isInSubnet(IPV6_MULTICAST_SUBNET);
};

/**
 * Returns `true` if `remote` is on a local-link subnet of any non-internal interface
 * this host owns, or is a loopback address.
 *
 * This is the no-native-deps approximation of RFC 6762 §11 inbound origin verification.
 * True §11 wants `IP_TTL === 255` on inbound, which Node's `dgram.Socket` does not
 * expose. Until a native `recvmsg` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` path lands, a
 * source-address subnet check rejects off-link injection in the common case.
 *
 * For `udp4`: accepts any address in `127.0.0.0/8`, plus any address that falls within
 * the CIDR subnet of a non-internal IPv4 interface from `os.networkInterfaces()`.
 *
 * For `udp6`: accepts `::1`, any `fe80::/10` link-local address, plus any address that
 * falls within the CIDR subnet of a non-internal IPv6 interface. An IPv6 zone-id
 * suffix (e.g. `%eth0`) on the input is stripped before parsing.
 *
 * `os.networkInterfaces()` is re-read on every call via {@link get_addresses}, so the
 * result reflects the current state of the system (no stale-cache window after a VPN
 * connect or NIC up/down event).
 *
 * @param remote - the source address from a received UDP datagram (e.g. `RemoteInfo.address`)
 * @param type - `'udp4'` if the receiving socket is IPv4, `'udp6'` if IPv6
 * @returns `true` if the source is on a local link of this host, `false` otherwise
 */
export const is_on_local_link = (remote: string, type: SocketType): boolean => {
    if (!remote) return false;

    const addrStr = remote.split('%')[0];

    if (type === 'udp4') {
        if (!Address4.isValid(addrStr)) return false;

        const addr = new Address4(addrStr);

        if (addr.isInSubnet(IPV4_LOOPBACK_SUBNET)) return true;

        for (const iface of get_addresses('udp4')) {
            if (addr.isInSubnet(iface as Address4)) return true;
        }

        return false;
    }

    if (!Address6.isValid(addrStr)) return false;

    const addr = new Address6(addrStr);

    if (addr.isLoopback()) return true;
    // RFC 4291 §2.4 reserves the entire FE80::/10 prefix for Link-Local unicast,
    // while §2.5.6 specifies the link-local address format with the middle 54
    // bits set to zero (effectively fe80::/64). Address6.isLinkLocal() enforces
    // the strict §2.5.6 format. For inbound source-address filtering the wider
    // §2.4 reservation is the safer membership test: any address in FE80::/10
    // is by definition not routable, so admitting the full prefix preserves
    // §2.5.6-compliant peers without rejecting nonstandard-but-on-link forms.
    if (addr.isInSubnet(IPV6_LINK_LOCAL_SUBNET)) return true;

    for (const iface of get_addresses('udp6')) {
        if (addr.isInSubnet(iface as Address6)) return true;
    }

    return false;
};
