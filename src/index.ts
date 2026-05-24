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

import { createSocket, RemoteInfo, Socket, SocketOptions, SocketType } from 'dgram';
import { AddressInfo } from 'net';
import { EventEmitter } from 'events';
import { Address4, Address6 } from 'ip-address';
import {
    compare_IP_addresses,
    detect_type,
    get_addresses,
    is_multicast,
    is_on_local_link,
    is_valid_ip
} from './helpers';
export { Address4, Address6 };

export class MulticastSocket extends EventEmitter {
    /**
     * Creates a new instance of a MulticastSocket. Use {@link MulticastSocket.create} instead
     * of calling this constructor directly.
     *
     * @param options - the options used to create this socket
     * @param type - the detected UDP socket type (`'udp4'` or `'udp6'`)
     * @param interfaces - the resolved network interfaces as parsed IP address objects
     * @param addresses - the resolved interface addresses as plain strings (without CIDR prefix)
     * @param multicastSocket - the underlying dgram socket bound to `0.0.0.0` or `::` for group traffic
     * @param unicastSockets - a map of interface address to its dedicated dgram unicast socket
     * @protected
     */
    protected constructor (
        public readonly options: MulticastSocket.Options,
        protected readonly type: SocketType,
        public readonly interfaces: (Address4 | Address6)[],
        public readonly addresses: string[],
        protected readonly multicastSocket: Socket,
        protected readonly unicastSockets: Map<string, Socket>
    ) {
        super();

        const multicastSocketAddress = this.multicastSocket.address();

        this.multicastSocket
            .on('close', () => this.emit('close', multicastSocketAddress))
            .on('connect', () => this.emit('connect', multicastSocketAddress))
            .on('error', error => this.emit('error', error, multicastSocketAddress))
            .on('message', (message: Buffer, rinfo: RemoteInfo) => {
                this.dispatch_message(message, multicastSocketAddress, rinfo);
            });

        this.unicastSockets.forEach(socket => {
            const address = socket.address();

            socket
                .on('close', () => this.emit('close', address))
                .on('connect', () => this.emit('connect', address))
                .on('error', error => this.emit('error', error, address))
                .on('message', (message: Buffer, rinfo: RemoteInfo) => {
                    this.dispatch_message(message, address, rinfo);
                });
        });
    }

    /**
     * Applies the inbound filters (`fromSelf` short-circuit and RFC 6762 §11
     * link-local origin check) and emits the appropriate event.
     *
     * RFC 6762 §11 carve-out: packets received with a destination address
     * equal to the well-known link-local multicast group are "necessarily
     * deemed to have originated on the local link, regardless of source IP
     * address." Only the shared multicast socket calls `addMembership`, so it
     * is the only socket that ever sees multicast-destination traffic. We
     * discriminate by `local.address`: the multicast socket binds to the
     * wildcard (`0.0.0.0` / `::`), the per-interface unicast sockets bind to
     * specific interface addresses. Packets arriving on the wildcard skip the
     * source-subnet check; packets arriving on a unicast bind still receive
     * the check (which is the §11 unicast-destination rule).
     */
    private dispatch_message (message: Buffer, local: AddressInfo, rinfo: RemoteInfo): void {
        const remoteBare = MulticastSocket.normalize_address(rinfo.address);
        const self = this.addresses.includes(remoteBare);

        if (!this.options.loopback && self) return;

        const arrivedOnMulticastSocket = MulticastSocket.is_wildcard_address(local.address);

        if (
            this.options.linkLocalOnly &&
            !arrivedOnMulticastSocket &&
            !is_on_local_link(rinfo.address, this.type)
        ) {
            this.emit('drop', message, local, rinfo, 'off-link');

            return;
        }

        this.emit('message', message, local, rinfo, self);
    }

    /**
     * Strips an IPv6 zone-id suffix (e.g. `%eth0`) from an address string for
     * comparison against our bound addresses (which are stored without
     * zone-ids). Used by `dispatch_message` for the fromSelf check and by
     * `send`/`create` for `srcAddress` / `host` matching.
     */
    private static normalize_address (address: string): string {
        return address.split('%')[0];
    }

    /**
     * Returns true if `address` is the IPv4 or IPv6 wildcard bind. Used by
     * `dispatch_message` to recognize packets arriving on the shared multicast
     * socket (which is wildcard-bound).
     */
    private static is_wildcard_address (address: string): boolean {
        return address === '0.0.0.0' || address === '::';
    }

    /**
     * Async factory that creates, binds, and returns a new {@link MulticastSocket}.
     *
     * Internally this creates one multicast dgram socket bound to `0.0.0.0` (or `::` for IPv6)
     * for group traffic, plus one unicast dgram socket per network interface for reliable
     * multi-interface sending and receiving.
     *
     * The socket type (`udp4` or `udp6`) is automatically detected from the
     * `multicastGroup` address provided in `options`.
     *
     * The `host` option controls which interfaces are used:
     * - If omitted, all available interfaces are used (similar to binding to `0.0.0.0` / `::`)
     * - If an IP address string, only that interface is used
     * - If a network interface name, all addresses assigned to that interface are used
     *
     * @param options - the configuration for the new socket
     * @returns a fully initialized {@link MulticastSocket} ready to send and receive
     * @throws Error if no usable interfaces are found, or if the specified host address
     *         does not exist on this system or does not match the multicast group address family
     */
    public static async create (options: MulticastSocket.Options): Promise<MulticastSocket> {
        options.reuseAddr ??= true;
        options.linkLocalOnly ??= true;

        const type = detect_type(options.multicastGroup);

        if (!is_multicast(options.multicastGroup, type)) {
            throw new Error(`multicastGroup ${options.multicastGroup} is not a multicast address`);
        }

        const multicastInterfaces = (() => {
            const addresses = get_addresses(type);
            const _addresses = addresses.map(address => address.address.split('/')[0]);

            // if not set, then assume all
            if (!options.host) return addresses;

            if (typeof options.host !== 'string') {
                options.host = options.host.address.split('/')[0];
            }

            // Strip any IPv6 zone-id from the host string before parsing/matching;
            // os.networkInterfaces() returns bare addresses without zone-ids.
            options.host = MulticastSocket.normalize_address(options.host);

            const iface = is_valid_ip(options.host);

            // check to see if the interface specified is an ip address
            if (iface) {
                // confirm that the interface address type matches the multicast address type
                if (detect_type(options.host) !== type) {
                    throw new Error('Interface address type does not match multicast address type');
                }

                // confirm that the interface address specified is actually on this system
                if (!_addresses.includes(options.host)) {
                    throw new Error(`Cannot use ${options.host} for multicast`);
                }

                // if we made it this far, then it's a valid address that we can use
                return [iface];
            }

            // if it wasn't a valid address, then it 'must' be an interface name
            return get_addresses(type, options.host);
        })().sort(compare_IP_addresses);

        if (multicastInterfaces.length === 0) {
            throw new Error('No usable interfaces found');
        }

        const multicastAddresses = multicastInterfaces.map(address => address.address.split('/')[0]);

        const create_and_bind_multicast_socket = async (): Promise<Socket> =>
            new Promise((resolve, reject) => {
                const socket = createSocket({ ...options, type });

                const handle_error = (error: Error) => {
                    socket.off('error', handle_error);

                    try { socket.close(); } catch {}

                    return reject(error);
                };

                socket.once('error', handle_error);

                socket.bind({
                    port: options.port,
                    address: type === 'udp4' ? '0.0.0.0' : '::',
                    exclusive: options.exclusive ?? false
                }, () => {
                    socket.off('error', handle_error);

                    socket.setTTL(255);
                    socket.setMulticastTTL(255);
                    socket.setMulticastLoopback(options.loopback ?? false);

                    for (const address of multicastAddresses) {
                        try {
                            socket.addMembership(options.multicastGroup, address);
                        } catch (error: any) {
                            socket.close();

                            return reject(error);
                        }
                    }

                    return resolve(socket);
                });
            });

        const create_and_bind_unicast_socket = async (address: string): Promise<Socket> =>
            new Promise((resolve, reject) => {
                const socket = createSocket({ type, reuseAddr: true, reusePort: options.reusePort ?? false });

                const handle_error = (error: Error) => {
                    socket.off('error', handle_error);

                    try { socket.close(); } catch {}

                    return reject(error);
                };

                socket.once('error', handle_error);

                socket.bind({ address, exclusive: options.exclusive ?? false }, () => {
                    socket.off('error', handle_error);

                    // RFC 6762 §11: outbound multicast must carry IP TTL/Hop Limit 255.
                    // Default send() uses the per-interface unicast sockets, so they
                    // need IP_MULTICAST_TTL set explicitly, otherwise the kernel default
                    // (typically 1) leaks out and breaks off-link receive verification.
                    socket.setTTL(255);
                    socket.setMulticastTTL(255);

                    return resolve(socket);
                });
            });

        const unicastSockets = new Map<string, Socket>();

        const cleanup_sockets = (sockets: Iterable<Socket>) => {
            for (const socket of sockets) {
                try { socket.close(); } catch {}
            }
        };

        try {
            for (const address of multicastAddresses) {
                const socket = await create_and_bind_unicast_socket(address);

                unicastSockets.set(address, socket);
            }
        } catch (error: any) {
            cleanup_sockets(unicastSockets.values());

            throw error;
        }

        let multicastSocket: Socket;

        try {
            multicastSocket = await create_and_bind_multicast_socket();
        } catch (error: any) {
            cleanup_sockets(unicastSockets.values());

            throw error;
        }

        return new MulticastSocket(
            options,
            type,
            multicastInterfaces,
            multicastAddresses,
            multicastSocket,
            unicastSockets);
    }

    /**
     * Registers a listener for the given event.
     *
     * Events:
     * - `'message'`: emitted when a UDP message is received and passes all inbound
     *   filters. The listener receives the raw message buffer, the local
     *   {@link AddressInfo} of the receiving socket, the {@link RemoteInfo} of the
     *   sender, and a `fromSelf` boolean indicating whether the message originated
     *   from this instance.
     * - `'drop'`: emitted when an inbound message is rejected by a filter. Currently
     *   the only reason is `'off-link'` (RFC 6762 §11 link-local origin check failed
     *   while `options.linkLocalOnly` was true). The listener receives the message,
     *   the local address, the remote address, and the reason string.
     * - `'close'`: emitted when an underlying socket is closed.
     * - `'connect'`: emitted when an underlying socket connects.
     * - `'error'`: emitted when an underlying socket encounters an error.
     *
     * @param event - the event name
     * @param listener - the callback to invoke when the event is emitted
     */
    public on(event: 'close', listener: (local: AddressInfo) => void): this;
    public on(event: 'connect', listener: (local: AddressInfo) => void): this;
    public on(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public on(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public on(event: 'drop', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        reason: MulticastSocket.DropReason
    ) => void): this;

    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    /**
     * Registers a one-time listener for the given event. The listener is automatically
     * removed after it fires once.
     *
     * @param event - the event name
     * @param listener - the callback to invoke when the event is emitted
     */
    public once(event: 'close', listener: (local: AddressInfo) => void): this;
    public once(event: 'connect', listener: (local: AddressInfo) => void): this;
    public once(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public once(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public once(event: 'drop', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        reason: MulticastSocket.DropReason
    ) => void): this;

    public once (event: any, listener: (...args: any[]) => void): this {
        return super.once(event, listener);
    }

    /**
     * Removes a previously registered listener for the given event.
     *
     * @param event - the event name
     * @param listener - the callback to remove
     */
    public off(event: 'close', listener: (local: AddressInfo) => void): this;
    public off(event: 'connect', listener: (local: AddressInfo) => void): this;
    public off(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public off(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public off(event: 'drop', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        reason: MulticastSocket.DropReason
    ) => void): this;

    public off (event: any, listener: (...args: any[]) => void): this {
        return super.off(event, listener);
    }

    /**
     * Sends a message to the multicast group (or a unicast destination).
     *
     * Socket selection:
     * - By default, the message is sent from **all** underlying unicast sockets, ensuring
     *   it goes out on every bound interface.
     * - If `options.srcAddress` is set, only the unicast socket for that address is used.
     * - If `options.useMulticastSocket` is set, the shared multicast socket is used instead.
     *   When combined with `options.srcAddress`, the multicast interface is set accordingly;
     *   without it, the OS chooses the outgoing interface, which may not cover all interfaces.
     *
     * Destination:
     * - Defaults to the multicast group address and port from the constructor options.
     * - Override with `options.dstAddress` and/or `options.dstPort` to send via unicast
     *   or to a different port.
     *
     * Partial failures are collected rather than thrown. Use {@link Promise.allSettled} semantics
     * internally so that a failure on one interface does not prevent sending on others.
     *
     * Concurrency note: combining `useMulticastSocket: true` with `srcAddress` mutates per-socket
     * interface state on the shared multicast socket via `setMulticastInterface`. Two such calls
     * issued without awaiting the first to complete will race and may send on the wrong
     * interface. Serialize them in the caller, or omit `useMulticastSocket` (the default
     * per-interface unicast path is race-free because each interface has its own socket).
     *
     * @param message - the payload to send
     * @param options - optional send configuration
     * @returns an array of errors for any interfaces that failed to send (empty on full success)
     * @throws Error if `options.srcAddress` is specified but no matching socket exists
     */
    public async send (
        message: string | NodeJS.ArrayBufferView | readonly any[],
        options: MulticastSocket.Send.Options = {}
    ): Promise<Error[]> {
        let sockets: Socket[] = [];

        if (options.useMulticastSocket) {
            sockets = [this.multicastSocket];

            if (options.srcAddress) {
                if (typeof options.srcAddress !== 'string') {
                    options.srcAddress = options.srcAddress.address.split('/')[0];
                }

                options.srcAddress = MulticastSocket.normalize_address(options.srcAddress);

                if (!this.addresses.includes(options.srcAddress)) {
                    throw new Error(`Cannot use ${options.srcAddress} with multicast socket`);
                }

                this.multicastSocket.setMulticastInterface(options.srcAddress);
            }
        } else if (options.srcAddress) {
            if (typeof options.srcAddress !== 'string') {
                options.srcAddress = options.srcAddress.address.split('/')[0];
            }

            options.srcAddress = MulticastSocket.normalize_address(options.srcAddress);

            const candidate_socket = this.unicastSockets.get(options.srcAddress);

            if (!candidate_socket) {
                throw new Error('No unicast socket is available for the specified address');
            }

            sockets = [candidate_socket];
        } else {
            sockets = [...this.unicastSockets.values()];
        }

        let { dstAddress, dstPort } = options;
        dstAddress ??= this.options.multicastGroup;
        dstPort ??= this.options.port;

        if (typeof dstAddress !== 'string') {
            dstAddress = dstAddress.address.split('/')[0];
        }

        const send_on_socket = (socket: Socket): Promise<Socket> =>
            new Promise((resolve, reject) => {
                socket.send(message, dstPort, dstAddress, error => {
                    if (error) return reject(error);

                    return resolve(socket);
                });
            });

        const results = await Promise.allSettled(sockets.map(send_on_socket));

        return results.filter(result => result.status === 'rejected')
            .map(failure => {
                const idx = results.indexOf(failure);
                const socket = sockets[idx];
                const { address, port } = socket.address();

                return new Error(
                    `Send failed on socket bound to ${address}:${port} - ${failure.reason?.message || failure.reason}`);
            });
    }

    /**
     * Returns the address information for all underlying sockets (the multicast socket
     * plus each per-interface unicast socket).
     *
     * Each entry contains `address`, `family`, and `port` properties.
     */
    public get addressInfo (): AddressInfo[] {
        const result: AddressInfo[] = [this.multicastSocket.address()];

        for (const [, socket] of this.unicastSockets) {
            result.push(socket.address());
        }

        return result;
    }

    /**
     * Sets or clears the `IP_MULTICAST_LOOP` socket option on the shared multicast socket.
     * When set to `true`, multicast packets sent by this instance will also be delivered to
     * its own `'message'` event listeners (with `fromSelf` set to `true`).
     *
     * Implementation note: this only mutates `IP_MULTICAST_LOOP` on the shared multicast
     * socket; the per-interface unicast sockets retain their OS-default loopback. The
     * authoritative gate for whether the caller sees its own packets is the
     * `loopback` check inside `dispatch_message`, which reads `options.loopback` that
     * this method updates. The user-visible contract is therefore honored regardless of
     * the kernel-level state on the unicast sockets.
     *
     * @param loopback - whether to enable multicast loopback
     */
    public setMulticastLoopback (loopback: boolean): void {
        this.options.loopback = loopback;

        this.multicastSocket.setMulticastLoopback(loopback);
    }

    /**
     * Closes all underlying sockets and stops listening for data. Drops multicast group
     * membership on each interface before closing the multicast socket.
     *
     * Prefer {@link destroy} for full cleanup, which also removes all event listeners.
     */
    public async close (): Promise<void> {
        const close = async (socket: Socket): Promise<void> =>
            new Promise(resolve => {
                try {
                    socket.close(() => resolve());
                } catch {
                    return resolve();
                }
            });

        for (const [, socket] of this.unicastSockets) {
            await close(socket);
        }

        for (const address of this.addresses) {
            try {
                this.multicastSocket.dropMembership(this.options.multicastGroup, address);
            } catch {}
        }

        return close(this.multicastSocket);
    }

    /**
     * Closes all underlying sockets and removes all event listeners from both the
     * internal dgram sockets and this {@link MulticastSocket} instance. This is the
     * recommended way to fully tear down a socket.
     */
    public async destroy (): Promise<void> {
        try {
            await this.close();
        } finally {
            for (const [, socket] of this.unicastSockets) {
                socket.removeAllListeners();
            }

            this.multicastSocket.removeAllListeners();

            this.removeAllListeners();
        }
    }

    /**
     * Adds all underlying sockets back to the Node.js event loop reference count, restoring
     * the default behavior where the process will not exit while the sockets are open.
     *
     * Call this to undo a previous {@link unref} call.
     */
    public ref (): void {
        for (const [, socket] of this.unicastSockets) {
            socket.ref();
        }

        this.multicastSocket.ref();
    }

    /**
     * Excludes all underlying sockets from the Node.js event loop reference count, allowing
     * the process to exit even if the sockets are still open.
     *
     * Call {@link ref} to restore the default behavior.
     */
    public unref (): void {
        for (const [, socket] of this.unicastSockets) {
            socket.unref();
        }

        this.multicastSocket.unref();
    }
}

export namespace MulticastSocket {
    export type Options = Omit<SocketOptions, 'type'> & {
        /**
         * The local port to which the multicast socket is bound.
         */
        port: number;
        /**
         * The local host to bind to. Accepts an IPv4 address, IPv6 address, or a network
         * interface name (e.g. `'eth0'`). If omitted, all available interfaces are used.
         *
         * When an IP address is provided, only the matching interface is used. When an
         * interface name is provided, all addresses assigned to that interface are used.
         * The address family must match the `multicastGroup` (IPv4 group requires IPv4 host).
         */
        host?: string | Address4 | Address6;
        /**
         * When `false` (the default), cluster workers share the same underlying socket handle.
         * When `true`, the handle is not shared and attempted port sharing results in an error.
         *
         * Note: setting `reusePort` to `true` implicitly forces `exclusive` to `true`.
         */
        exclusive?: boolean;
        /**
         * The multicast group address to join (e.g. `'224.0.0.251'` for IPv4).
         */
        multicastGroup: string;
        /**
         * When `true`, the instance will also receive its own outgoing multicast packets
         * via the `'message'` event (with `fromSelf` set to `true`).
         * @default false
         */
        loopback?: boolean;
        /**
         * RFC 6762 §11 inbound origin verification (no-native-deps approximation).
         *
         * When `true` (the default), received messages whose source address is not on a
         * local-link subnet of any interface this host owns (plus loopback) are dropped
         * before the `'message'` event fires. Dropped packets are surfaced via the
         * `'drop'` event with reason `'off-link'`.
         *
         * Set to `false` for receive scenarios that legitimately cross routed segments
         * (e.g. SSDP over Layer 3, multicast across VPN tunnels).
         *
         * True §11 wants `IP_TTL === 255` on inbound, which Node's `dgram.Socket` does
         * not expose; the subnet check is the interim until a native-addon receive path
         * is available.
         * @default true
         */
        linkLocalOnly?: boolean;
    }

    /**
     * Reason a packet was dropped before the `'message'` event would have fired.
     *
     * - `'off-link'`: source address failed the `linkLocalOnly` check (RFC 6762 §11).
     */
    export type DropReason = 'off-link';

    export namespace Send {
        export type Options = {
            /**
             * If `true`, sends the packet via the shared multicast socket instead of the
             * per-interface unicast sockets. Combine with `srcAddress` to control which
             * interface the multicast socket uses; without it, the OS chooses the interface.
             *
             * Concurrency caveat: when `useMulticastSocket` and `srcAddress` are combined,
             * the call sequence `setMulticastInterface(srcAddress)` then `send(...)` mutates
             * per-socket state on the shared multicast socket. Concurrent calls with
             * different `srcAddress` values will race. Serialize them in the caller or use
             * the default per-interface unicast path, which is race-free.
             * @default false
             */
            useMulticastSocket?: boolean;
            /**
             * The source address to use for the outgoing packet.
             *
             * If not specified (and `useMulticastSocket` is not set), the packet is sent
             * from all underlying unicast sockets.
             */
            srcAddress?: string | Address4 | Address6;
            /**
             * The destination address for the outgoing packet.
             *
             * Defaults to the `multicastGroup` address from the constructor options.
             * Set this to send a unicast message to a specific host instead.
             */
            dstAddress?: string | Address4 | Address6;
            /**
             * The destination port for the outgoing packet.
             *
             * Defaults to the `port` from the constructor options.
             */
            dstPort?: number;
        }
    }
}

export default MulticastSocket;
