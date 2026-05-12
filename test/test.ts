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

import { describe, it, before, after } from 'node:test';
import MulticastSocket, { Address4, Address6 } from '../src';
import { compare_IP_addresses, detect_type, get_addresses, is_on_local_link, is_valid_ip } from '../src/helpers';
import assert from 'assert';

describe('Helper Functions', () => {
    describe('detect_type()', () => {
        it('returns udp4 for IPv4 string', () => {
            assert.strictEqual(detect_type('192.168.1.1'), 'udp4');
        });

        it('returns udp4 for multicast IPv4 string', () => {
            assert.strictEqual(detect_type('224.0.0.251'), 'udp4');
        });

        it('returns udp6 for IPv6 loopback string', () => {
            assert.strictEqual(detect_type('::1'), 'udp6');
        });

        it('returns udp6 for multicast IPv6 string', () => {
            assert.strictEqual(detect_type('ff02::1'), 'udp6');
        });

        it('returns udp4 for Address4 object', () => {
            assert.strictEqual(detect_type(new Address4('192.168.1.1')), 'udp4');
        });

        it('returns udp6 for Address6 object', () => {
            assert.strictEqual(detect_type(new Address6('::1')), 'udp6');
        });

        it('throws for invalid address string', () => {
            assert.throws(() => detect_type('not-an-address'), /Invalid IP address/);
        });

        it('throws for empty string', () => {
            assert.throws(() => detect_type(''), /Invalid IP address/);
        });
    });

    describe('is_valid_ip()', () => {
        it('returns Address4 for valid IPv4', () => {
            const result = is_valid_ip('192.168.1.1');
            assert.ok(result instanceof Address4);
        });

        it('returns Address4 for IPv4 edge cases', () => {
            assert.ok(is_valid_ip('0.0.0.0') instanceof Address4);
            assert.ok(is_valid_ip('255.255.255.255') instanceof Address4);
        });

        it('returns Address6 for valid IPv6', () => {
            const result = is_valid_ip('::1');
            assert.ok(result instanceof Address6);
        });

        it('returns Address6 for link-local IPv6', () => {
            const result = is_valid_ip('fe80::1');
            assert.ok(result instanceof Address6);
        });

        it('returns undefined for invalid address', () => {
            assert.strictEqual(is_valid_ip('not-valid'), undefined);
        });

        it('returns undefined for empty string', () => {
            assert.strictEqual(is_valid_ip(''), undefined);
        });

        it('returns undefined for partial IPv4', () => {
            assert.strictEqual(is_valid_ip('192.168'), undefined);
        });
    });

    describe('compare_IP_addresses()', () => {
        it('returns 0 for equal IPv4 addresses', () => {
            const a = new Address4('10.0.0.1');
            const b = new Address4('10.0.0.1');
            assert.strictEqual(compare_IP_addresses(a, b), 0);
        });

        it('returns -1 when first IPv4 is less', () => {
            const a = new Address4('10.0.0.1');
            const b = new Address4('10.0.0.2');
            assert.strictEqual(compare_IP_addresses(a, b), -1);
        });

        it('returns 1 when first IPv4 is greater', () => {
            const a = new Address4('10.0.0.2');
            const b = new Address4('10.0.0.1');
            assert.strictEqual(compare_IP_addresses(a, b), 1);
        });

        it('compares across subnets correctly', () => {
            const a = new Address4('10.0.0.255');
            const b = new Address4('10.0.1.0');
            assert.strictEqual(compare_IP_addresses(a, b), -1);
        });

        it('returns 0 for equal IPv6 addresses', () => {
            const a = new Address6('::1');
            const b = new Address6('::1');
            assert.strictEqual(compare_IP_addresses(a, b), 0);
        });

        it('returns -1 when first IPv6 is less', () => {
            const a = new Address6('::1');
            const b = new Address6('::2');
            assert.strictEqual(compare_IP_addresses(a, b), -1);
        });

        it('returns 1 when first IPv6 is greater', () => {
            const a = new Address6('::2');
            const b = new Address6('::1');
            assert.strictEqual(compare_IP_addresses(a, b), 1);
        });

        it('can be used as an Array.sort comparator', () => {
            const addrs = [
                new Address4('10.0.0.3'),
                new Address4('10.0.0.1'),
                new Address4('10.0.0.2')
            ];
            addrs.sort(compare_IP_addresses);
            assert.strictEqual(addrs[0].address, '10.0.0.1');
            assert.strictEqual(addrs[1].address, '10.0.0.2');
            assert.strictEqual(addrs[2].address, '10.0.0.3');
        });
    });

    describe('get_addresses()', () => {
        it('returns an array for udp4', () => {
            const result = get_addresses('udp4');
            assert.ok(Array.isArray(result));
        });

        it('returns an array for udp6', () => {
            const result = get_addresses('udp6');
            assert.ok(Array.isArray(result));
        });

        it('udp4 results are all Address4 instances', () => {
            const result = get_addresses('udp4');
            for (const addr of result) {
                assert.ok(addr instanceof Address4);
            }
        });

        it('udp6 results are all Address6 instances', () => {
            const result = get_addresses('udp6');
            for (const addr of result) {
                assert.ok(addr instanceof Address6);
            }
        });

        it('returns empty array for non-existent interface name', () => {
            const result = get_addresses('udp4', 'nonexistent_iface_xyz');
            assert.strictEqual(result.length, 0);
        });

        it('addresses include CIDR prefix', () => {
            const result = get_addresses('udp4');
            for (const addr of result) {
                assert.ok(
                    addr.address.includes('/'),
                    `Expected CIDR prefix in ${addr.address}`
                );
            }
        });

        it('does not return internal/loopback addresses', () => {
            const result = get_addresses('udp4');
            for (const addr of result) {
                const ip = addr.address.split('/')[0];
                assert.notStrictEqual(ip, '127.0.0.1');
            }
        });
    });

    describe('is_on_local_link()', () => {
        it('returns true for 127.0.0.1 (udp4)', () => {
            assert.strictEqual(is_on_local_link('127.0.0.1', 'udp4'), true);
        });

        it('returns true for arbitrary 127.0.0.0/8 (udp4)', () => {
            assert.strictEqual(is_on_local_link('127.0.0.5', 'udp4'), true);
            assert.strictEqual(is_on_local_link('127.255.255.254', 'udp4'), true);
        });

        it('returns true for ::1 (udp6)', () => {
            assert.strictEqual(is_on_local_link('::1', 'udp6'), true);
        });

        it('returns true for link-local fe80::/10 (udp6)', () => {
            assert.strictEqual(is_on_local_link('fe80::1', 'udp6'), true);
            assert.strictEqual(is_on_local_link('febf::ffff', 'udp6'), true);
        });

        it('strips an IPv6 zone-id before evaluating (udp6)', () => {
            assert.strictEqual(is_on_local_link('fe80::1%eth0', 'udp6'), true);
            assert.strictEqual(is_on_local_link('::1%lo', 'udp6'), true);
        });

        it('returns false for a routable IPv4 (udp4)', () => {
            assert.strictEqual(is_on_local_link('8.8.8.8', 'udp4'), false);
            // RFC 5737 TEST-NET-3, guaranteed not in any iface subnet
            assert.strictEqual(is_on_local_link('203.0.113.1', 'udp4'), false);
        });

        it('returns false for a routable IPv6 GUA (udp6)', () => {
            assert.strictEqual(is_on_local_link('2001:4860:4860::8888', 'udp6'), false);
        });

        it('returns false for empty input', () => {
            assert.strictEqual(is_on_local_link('', 'udp4'), false);
            assert.strictEqual(is_on_local_link('', 'udp6'), false);
        });

        it('returns false for an IPv6 string passed with udp4', () => {
            assert.strictEqual(is_on_local_link('fe80::1', 'udp4'), false);
        });

        it('returns false for an IPv4 string passed with udp6', () => {
            assert.strictEqual(is_on_local_link('192.168.1.1', 'udp6'), false);
        });

        it('returns true for every udp4 interface address on this host', () => {
            for (const iface of get_addresses('udp4')) {
                const addrStr = iface.address.split('/')[0];
                assert.strictEqual(
                    is_on_local_link(addrStr, 'udp4'),
                    true,
                    `Expected ${addrStr} to be on-link`
                );
            }
        });

        it('returns true for every udp6 interface address on this host', () => {
            for (const iface of get_addresses('udp6')) {
                const addrStr = iface.address.split('/')[0];
                assert.strictEqual(
                    is_on_local_link(addrStr, 'udp6'),
                    true,
                    `Expected ${addrStr} to be on-link`
                );
            }
        });
    });
});

describe('MulticastSocket', () => {
    describe('create() - error cases', () => {
        it('throws for invalid multicast group address', async () => {
            await assert.rejects(
                () => MulticastSocket.create({
                    port: 5959,
                    multicastGroup: 'not-an-address'
                }),
                /Invalid IP address/
            );
        });

        it('throws when host type does not match multicast group type', async () => {
            await assert.rejects(
                () => MulticastSocket.create({
                    port: 5959,
                    multicastGroup: '224.0.0.251',
                    host: '::1'
                }),
                /does not match/
            );
        });

        it('throws when host address is not on this system', async () => {
            await assert.rejects(
                () => MulticastSocket.create({
                    port: 5959,
                    multicastGroup: '224.0.0.251',
                    host: '192.168.254.254'
                }),
                /Cannot use/
            );
        });

        it('throws for non-existent interface name', async () => {
            await assert.rejects(
                () => MulticastSocket.create({
                    port: 5959,
                    multicastGroup: '224.0.0.251',
                    host: 'nonexistent_iface_xyz'
                }),
                /No usable interfaces found/
            );
        });
    });

    describe('create() - defaults', () => {
        let socket: MulticastSocket;

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('sets reuseAddr to true by default', async () => {
            socket = await MulticastSocket.create({
                port: 5960,
                multicastGroup: '224.0.0.251'
            });

            assert.strictEqual(socket.options.reuseAddr, true);
        });
    });

    describe('create() - with Address4 host', () => {
        let socket: MulticastSocket;

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('accepts an Address4 object as host', { skip: false }, async (t) => {
            const addrs = get_addresses('udp4');
            if (addrs.length === 0) return t.skip('No udp4 addresses available');

            socket = await MulticastSocket.create({
                port: 5961,
                multicastGroup: '224.0.0.251',
                host: addrs[0]
            });

            assert.strictEqual(socket.addresses.length, 1);
        });
    });

    describe('socket properties', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5962,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('has non-empty addresses', () => {
            assert.notStrictEqual(socket.addresses.length, 0);
        });

        it('has non-empty interfaces', () => {
            assert.notStrictEqual(socket.interfaces.length, 0);
        });

        it('has non-empty addressInfo', () => {
            assert.notStrictEqual(socket.addressInfo.length, 0);
        });

        it('addresses are valid IPv4 strings without CIDR', () => {
            for (const addr of socket.addresses) {
                assert.ok(
                    Address4.isValid(addr),
                    `${addr} is not a valid IPv4`
                );
                assert.ok(
                    !addr.includes('/'),
                    `${addr} should not contain CIDR prefix`
                );
            }
        });

        it('interfaces are Address4 instances', () => {
            for (const iface of socket.interfaces) {
                assert.ok(iface instanceof Address4);
            }
        });

        it('interfaces are sorted by numeric value', () => {
            for (let i = 1; i < socket.interfaces.length; i++) {
                const cmp = compare_IP_addresses(
                    socket.interfaces[i - 1],
                    socket.interfaces[i]
                );
                assert.ok(cmp <= 0, 'Interfaces should be sorted');
            }
        });

        it('addressInfo entries have valid structure', () => {
            for (const info of socket.addressInfo) {
                assert.ok(typeof info.address === 'string');
                assert.ok(typeof info.port === 'number');
                assert.ok(info.port >= 0);
            }
        });

        it('addressInfo includes multicast socket on configured port', () => {
            const found = socket.addressInfo.some(
                info => info.port === 5962
            );
            assert.ok(found, 'Should have a socket on port 5962');
        });

        it('addressInfo count equals interfaces + 1', () => {
            assert.strictEqual(
                socket.addressInfo.length,
                socket.interfaces.length + 1
            );
        });

        it('addresses count matches interfaces count', () => {
            assert.strictEqual(
                socket.addresses.length,
                socket.interfaces.length
            );
        });

        it('options are stored correctly', () => {
            assert.strictEqual(socket.options.port, 5962);
            assert.strictEqual(socket.options.multicastGroup, '224.0.0.251');
            assert.strictEqual(socket.options.loopback, true);
        });
    });

    describe('linkLocalOnly option', () => {
        it('defaults to true', async () => {
            const socket = await MulticastSocket.create({
                port: 5980,
                multicastGroup: '224.0.0.251'
            });

            try {
                assert.strictEqual(socket.options.linkLocalOnly, true);
            } finally {
                await socket.destroy();
            }
        });

        it('passes explicit false through', async () => {
            const socket = await MulticastSocket.create({
                port: 5981,
                multicastGroup: '224.0.0.251',
                linkLocalOnly: false
            });

            try {
                assert.strictEqual(socket.options.linkLocalOnly, false);
            } finally {
                await socket.destroy();
            }
        });

        it('emits drop and suppresses message for off-link source when enabled', async () => {
            const socket = await MulticastSocket.create({
                port: 5982,
                multicastGroup: '224.0.0.251'
            });

            try {
                let droppedReason: string | undefined;
                let messageFired = false;

                socket.on('drop', (_msg, _local, _remote, reason) => {
                    droppedReason = reason;
                });
                socket.on('message', () => {
                    messageFired = true;
                });

                // Synthesize an off-link receive on the underlying multicast socket.
                // 203.0.113.1 is RFC 5737 TEST-NET-3, guaranteed not on any local link.
                const underlying = (socket as any).multicastSocket;
                underlying.emit('message', Buffer.from('off-link'), {
                    address: '203.0.113.1',
                    family: 'IPv4',
                    port: 5959,
                    size: 8
                });

                assert.strictEqual(droppedReason, 'off-link');
                assert.strictEqual(messageFired, false);
            } finally {
                await socket.destroy();
            }
        });

        it('passes off-link source through when disabled', async () => {
            const socket = await MulticastSocket.create({
                port: 5983,
                multicastGroup: '224.0.0.251',
                linkLocalOnly: false
            });

            try {
                let droppedReason: string | undefined;
                let messageFired = false;

                socket.on('drop', (_msg, _local, _remote, reason) => {
                    droppedReason = reason;
                });
                socket.on('message', () => {
                    messageFired = true;
                });

                const underlying = (socket as any).multicastSocket;
                underlying.emit('message', Buffer.from('off-link'), {
                    address: '203.0.113.1',
                    family: 'IPv4',
                    port: 5959,
                    size: 8
                });

                assert.strictEqual(droppedReason, undefined);
                assert.strictEqual(messageFired, true);
            } finally {
                await socket.destroy();
            }
        });

        it('emits drop on the per-interface unicast socket path too', async () => {
            const socket = await MulticastSocket.create({
                port: 5984,
                multicastGroup: '224.0.0.251'
            });

            try {
                if (socket.addresses.length === 0) {
                    await socket.destroy();
                    return;
                }

                let droppedReason: string | undefined;

                socket.on('drop', (_msg, _local, _remote, reason) => {
                    droppedReason = reason;
                });

                const unicast = (socket as any).unicastSockets.get(socket.addresses[0]);
                unicast.emit('message', Buffer.from('off-link'), {
                    address: '203.0.113.1',
                    family: 'IPv4',
                    port: 5959,
                    size: 8
                });

                assert.strictEqual(droppedReason, 'off-link');
            } finally {
                await socket.destroy();
            }
        });
    });

    describe('setTTL()', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5963,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('does not throw for valid TTL', () => {
            socket.setTTL(128);
        });

        it('accepts TTL of 1', () => {
            socket.setTTL(1);
        });

        it('accepts TTL of 255', () => {
            socket.setTTL(255);
        });
    });

    describe('setMulticastLoopback()', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5964,
                multicastGroup: '224.0.0.251',
                loopback: false
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('updates options.loopback when enabling', () => {
            assert.strictEqual(socket.options.loopback, false);
            socket.setMulticastLoopback(true);
            assert.strictEqual(socket.options.loopback, true);
        });

        it('updates options.loopback when disabling', () => {
            socket.setMulticastLoopback(false);
            assert.strictEqual(socket.options.loopback, false);
        });
    });

    describe('ref() and unref()', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5965,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('ref() does not throw', () => {
            socket.ref();
        });

        it('unref() does not throw', () => {
            socket.unref();
        });

        it('ref() after unref() does not throw', () => {
            socket.unref();
            socket.ref();
        });
    });

    describe('send() options', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5966,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('send() returns an array', async () => {
            const errors = await socket.send(Buffer.from('test'));
            assert.ok(Array.isArray(errors));
        });

        it('send() with srcAddress string', { skip: false }, async (t) => {
            if (socket.addresses.length === 0) return t.skip('No addresses available');

            const errors = await socket.send(Buffer.from('test'), {
                srcAddress: socket.addresses[0]
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() with srcAddress as Address4', { skip: false }, async (t) => {
            if (socket.addresses.length === 0) return t.skip('No addresses available');

            const addr = new Address4(socket.addresses[0]);
            const errors = await socket.send(Buffer.from('test'), {
                srcAddress: addr
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() with useMulticastSocket', async () => {
            const errors = await socket.send(Buffer.from('test'), {
                useMulticastSocket: true
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() with useMulticastSocket and srcAddress', { skip: false }, async (t) => {
            if (socket.addresses.length === 0) return t.skip('No addresses available');

            const errors = await socket.send(Buffer.from('test'), {
                useMulticastSocket: true,
                srcAddress: socket.addresses[0]
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() with custom dstPort', async () => {
            const errors = await socket.send(Buffer.from('test'), {
                dstPort: 5999
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() with dstAddress as Address4', async () => {
            const errors = await socket.send(Buffer.from('test'), {
                dstAddress: new Address4('224.0.0.251')
            });
            assert.ok(Array.isArray(errors));
        });

        it('send() accepts string message', async () => {
            const errors = await socket.send('hello world');
            assert.ok(Array.isArray(errors));
        });

        it('send() accepts empty buffer', async () => {
            const errors = await socket.send(Buffer.alloc(0));
            assert.ok(Array.isArray(errors));
        });

        it('send() throws for invalid srcAddress on unicast', async () => {
            await assert.rejects(
                () => socket.send(Buffer.from('test'), {
                    srcAddress: '192.168.254.254'
                }),
                /No unicast socket is available/
            );
        });

        it('send() throws for invalid srcAddress with multicast', async () => {
            await assert.rejects(
                () => socket.send(Buffer.from('test'), {
                    useMulticastSocket: true,
                    srcAddress: '192.168.254.254'
                }),
                /Cannot use/
            );
        });
    });

    describe('send & receive', () => {
        let socket: MulticastSocket;
        const message = Buffer.from('This is a test message');

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5967,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('receives own message with fromSelf=true', { skip: false }, async (t) => {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    return reject(
                        new Error('Timeout waiting for multicast message')
                    );
                }, 1000);

                socket.once('message', (rmsg, _local, _remote, fromSelf) => {
                    clearTimeout(timeout);
                    if (rmsg.equals(message) && fromSelf) return resolve();
                    return reject(new Error('Message mismatch or not self'));
                });

                socket.send(message).then(errors => {
                    if (errors.length > 0) {
                        clearTimeout(timeout);
                        t.skip('Send returned errors');

                        return resolve();
                    }
                });
            });
        });

        it('received message has valid local AddressInfo', { skip: false }, async (t) => {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    return reject(new Error('Timeout waiting for message'));
                }, 1000);

                socket.once('message', (_msg, local) => {
                    clearTimeout(timeout);
                    try {
                        assert.ok(typeof local.address === 'string');
                        assert.ok(typeof local.port === 'number');
                        assert.ok(typeof local.family === 'string');
                        return resolve();
                    } catch (e) {
                        return reject(e);
                    }
                });

                socket.send(message).then(errors => {
                    if (errors.length > 0) {
                        clearTimeout(timeout);
                        t.skip('Send returned errors');

                        return resolve();
                    }
                });
            });
        });

        it('received message has valid remote RemoteInfo', { skip: false }, async (t) => {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    return reject(new Error('Timeout waiting for message'));
                }, 1000);

                socket.once('message', (_msg, _local, remote) => {
                    clearTimeout(timeout);
                    try {
                        assert.ok(typeof remote.address === 'string');
                        assert.ok(typeof remote.port === 'number');
                        assert.ok(typeof remote.size === 'number');
                        assert.strictEqual(remote.size, message.length);
                        return resolve();
                    } catch (e) {
                        return reject(e);
                    }
                });

                socket.send(message).then(errors => {
                    if (errors.length > 0) {
                        clearTimeout(timeout);
                        t.skip('Send returned errors');

                        return resolve();
                    }
                });
            });
        });

        it('sends and receives multiple messages', { skip: false }, async (t) => {
            const messages = [
                Buffer.from('message-1'),
                Buffer.from('message-2'),
                Buffer.from('message-3')
            ];
            const expected = new Set(messages.map(m => m.toString()));
            const seen = new Set<string>();

            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    return reject(new Error(
                        `Timeout: saw ${seen.size}/${messages.length}`
                    ));
                }, 3000);

                const handler = (
                    rmsg: Buffer,
                    _local: any,
                    _remote: any,
                    fromSelf: boolean
                ) => {
                    if (!fromSelf) return;
                    const str = rmsg.toString();
                    if (!expected.has(str)) return;
                    seen.add(str);
                    if (seen.size === messages.length) {
                        clearTimeout(timeout);
                        socket.off('message', handler);
                        try {
                            for (const msg of messages) {
                                assert.ok(
                                    seen.has(msg.toString()),
                                    `Missing: ${msg.toString()}`
                                );
                            }
                            return resolve();
                        } catch (e: any) {
                            return reject(e);
                        }
                    }
                };

                socket.on('message', handler);

                (async () => {
                    for (const msg of messages) {
                        const errors = await socket.send(msg);
                        if (errors.length > 0) {
                            clearTimeout(timeout);
                            socket.off('message', handler);
                            t.skip('Send returned errors');

                            return resolve();
                        }
                    }
                })();
            });
        });
    });

    describe('loopback behavior', () => {
        let socket: MulticastSocket;

        before(async () => {
            socket = await MulticastSocket.create({
                port: 5968,
                multicastGroup: '224.0.0.251',
                loopback: false
            });
        });

        after(async () => {
            if (socket) await socket.destroy();
        });

        it('does not receive own messages with loopback disabled', { skip: false }, async (t) => {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    // Expected: no message received
                    return resolve();
                }, 500);

                socket.once('message', (_m, _l, _r, fromSelf) => {
                    clearTimeout(timeout);
                    if (fromSelf) {
                        return reject(new Error(
                            'Should not receive own message'
                        ));
                    }
                    return resolve();
                });

                socket.send(Buffer.from('test')).then(errors => {
                    if (errors.length > 0) {
                        clearTimeout(timeout);
                        t.skip('Send returned errors');

                        return resolve();
                    }
                });
            });
        });
    });

    describe('close() and destroy()', () => {
        it('close() resolves without error', async () => {
            const socket = await MulticastSocket.create({
                port: 5969,
                multicastGroup: '224.0.0.251',
                loopback: true
            });

            await socket.close();
            await socket.destroy();
        });

        it('destroy() resolves without error', async () => {
            const socket = await MulticastSocket.create({
                port: 5970,
                multicastGroup: '224.0.0.251',
                loopback: true
            });

            await socket.destroy();
        });

        it('destroy() removes all listeners', async () => {
            const socket = await MulticastSocket.create({
                port: 5971,
                multicastGroup: '224.0.0.251',
                loopback: true
            });

            socket.on('message', () => {});
            socket.on('error', () => {});
            assert.ok(socket.listenerCount('message') > 0);

            await socket.destroy();

            assert.strictEqual(socket.listenerCount('message'), 0);
            assert.strictEqual(socket.listenerCount('error'), 0);
            assert.strictEqual(socket.listenerCount('close'), 0);
        });

        it('close() can be called multiple times', async () => {
            const socket = await MulticastSocket.create({
                port: 5972,
                multicastGroup: '224.0.0.251',
                loopback: true
            });

            await socket.close();
            await socket.close();
            await socket.destroy();
        });

        it('destroy() can be called multiple times', async () => {
            const socket = await MulticastSocket.create({
                port: 5973,
                multicastGroup: '224.0.0.251',
                loopback: true
            });

            await socket.destroy();
            await socket.destroy();
        });
    });

    describe('two independent sockets', () => {
        let socket1: MulticastSocket;
        let socket2: MulticastSocket;

        before(async () => {
            socket1 = await MulticastSocket.create({
                port: 5974,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
            socket2 = await MulticastSocket.create({
                port: 5975,
                multicastGroup: '224.0.0.251',
                loopback: true
            });
        });

        after(async () => {
            if (socket1) await socket1.destroy();
            if (socket2) await socket2.destroy();
        });

        it('both have addresses', () => {
            assert.ok(socket1.addresses.length > 0);
            assert.ok(socket2.addresses.length > 0);
        });

        it('are different instances', () => {
            assert.notStrictEqual(socket1, socket2);
        });

        it('are on different ports', () => {
            assert.strictEqual(socket1.options.port, 5974);
            assert.strictEqual(socket2.options.port, 5975);
        });
    });
});
