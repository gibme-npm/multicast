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
 * @param a - the first address to compare
 * @param b - the second address to compare
 * @returns `-1` if `a < b`, `0` if equal, `1` if `a > b`
 */
export const compare_IP_addresses = (
    a: Address4 | Address6,
    b: Address4 | Address6
): -1 | 0 | 1 => {
    const diff = a.bigInt() - b.bigInt();

    return diff === BigInt(0) ? 0 : diff < BigInt(0) ? -1 : 1;
};

/**
 * Converts a dotted-decimal netmask (e.g. `'255.255.255.0'`) to its CIDR prefix length.
 *
 * @param mask - the netmask in dotted-decimal notation
 * @returns the number of leading `1` bits (e.g. `24` for `'255.255.255.0'`)
 */
const netmask_to_prefix = (mask: string): number =>
    mask.split('.')
        .map(Number)
        .map(octet => octet.toString(2).padStart(8, '0'))
        .join('')
        .replace(/0+$/, '') // Remove trailing zeroes
        .length;

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
                let address: Address4 | Address6;

                const parseable = addr.cidr ? addr.cidr : `${addr.address}/${netmask_to_prefix(addr.netmask)}`;

                if (type === 'udp4') {
                    address = new Address4(parseable);
                } else {
                    address = new Address6(parseable);
                }

                addresses.push(address);
            }
        }
    }

    return [...new Set(addresses)];
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
    // Wider than Address6.isLinkLocal(): that method requires bits 10-63 to be zero
    // (effectively fe80::/64). RFC 4291 reserves the entire fe80::/10 block for
    // link-local unicast, so accept the full prefix range here.
    if (addr.isInSubnet(IPV6_LINK_LOCAL_SUBNET)) return true;

    for (const iface of get_addresses('udp6')) {
        if (addr.isInSubnet(iface as Address6)) return true;
    }

    return false;
};
