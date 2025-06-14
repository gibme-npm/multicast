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
 * Detects the socket type based upon the ip address supplied
 *
 * @param address
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
 * Compare helper for ip addresses so that they are sorted by their actual value
 * instead of the string representation
 *
 * @param a
 * @param b
 */
export const compare_IP_addresses = (
    a: Address4 | Address6,
    b: Address4 | Address6
): -1 | 0 | 1 => {
    const diff = a.bigInt() - b.bigInt();

    return diff === BigInt(0) ? 0 : diff < BigInt(0) ? -1 : 1;
};

/**
 * Converts a netmask (255.255.255.255) to the prefix for CIDR notation
 * @param mask
 */
const netmask_to_prefix = (mask: string): number =>
    mask.split('.')
        .map(Number)
        .map(octet => octet.toString(2).padStart(8, '0'))
        .join('')
        .replace(/0+$/, '') // Remove trailing zeroes
        .length;

/**
 * Gets all the addresses on the system for the specified type of socket
 *
 * @param type
 * @param name
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
 * Checks to determine if the address specified is a valid IPv4 or IPv6 address
 *
 * @param address
 */
export const is_valid_ip = (address: string): Address4 | Address6 | undefined => {
    if (Address4.isValid(address)) return new Address4(address);
    if (Address6.isValid(address)) return new Address6(address);
};
