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
