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
import { compare_IP_addresses, detect_type, get_addresses, is_valid_ip } from './helpers';
export { Address4, Address6 };

export class MulticastSocket extends EventEmitter {
    /**
     * Creates a new instance of a MulticastSocket
     *
     * @param options
     * @param type
     * @param interfaces
     * @param addresses
     * @param multicastSocket
     * @param unicastSockets
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
                const self = this.addresses.includes(rinfo.address);

                if (!this.options.loopback && self) return;

                this.emit('message', message, multicastSocketAddress, rinfo, self);
            });

        this.unicastSockets.forEach(socket => {
            const address = socket.address();

            socket
                .on('close', () => this.emit('close', address))
                .on('connect', () => this.emit('connect', address))
                .on('error', error => this.emit('error', error, address))
                .on('message', (message: Buffer, rinfo: RemoteInfo) => {
                    const self = this.addresses.includes(rinfo.address);

                    if (!this.options.loopback && self) return;

                    this.emit('message', message, address, rinfo, self);
                });
        });
    }

    /**
     * Creates a new multicast socket using the supplied options.
     *
     * When creating an instance, the underlying socket(s) are created, the events are mapped
     * through to the instance of this class, the sockets are bound, and we're off to the races.
     *
     * Note: the socket type (udp4 or udp6) is automatically detected based upon
     * the type of `multicastGroup` supplied in the constructor options.
     *
     * Additionally, the `interface` supplied can be one of IPv4, IPv6, interface names, or undefined.
     *
     * If `interface` is undefined, we will listen on all available interfaces
     *      (similar to binding to `0.0.0.0` or `::`)
     *
     * If `interface` is an interface name, we will listen to all addresses assigned to that interface
     *
     * @param options
     */
    public static async create (options: MulticastSocket.Options): Promise<MulticastSocket> {
        options.reuseAddr ??= true;

        const type = detect_type(options.multicastGroup);

        const multicastInterfaces = (() => {
            const addresses = get_addresses(type);
            const _addresses = addresses.map(address => address.address.split('/')[0]);

            // if not set, then assume all
            if (!options.host) return addresses;

            if (typeof options.host !== 'string') {
                options.host = options.host.address.split('/')[0];
            }

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

    public on(event: 'close', listener: (local: AddressInfo) => void): this;
    public on(event: 'connect', listener: (local: AddressInfo) => void): this;
    public on(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public on(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    public once(event: 'close', listener: (local: AddressInfo) => void): this;
    public once(event: 'connect', listener: (local: AddressInfo) => void): this;
    public once(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public once(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public once (event: any, listener: (...args: any[]) => void): this {
        return super.once(event, listener);
    }

    public off(event: 'close', listener: (local: AddressInfo) => void): this;
    public off(event: 'connect', listener: (local: AddressInfo) => void): this;
    public off(event: 'error', listener: (error: Error, local?: AddressInfo) => void): this;
    public off(event: 'message', listener: (
        message: Buffer,
        local: AddressInfo,
        remote: RemoteInfo,
        fromSelf: boolean
    ) => void): this;

    public off (event: any, listener: (...args: any[]) => void): this {
        return super.off(event, listener);
    }

    /**
     * Sends the specified message via the socket
     *
     * By default, the packet will be sent out to the multicast group address from all
     * the underlying unicast sockets.
     *
     * If `options.useMulticastSocket` is set, the packet will only be sent out via
     * the underlying multicast socket; however, the behavior for this is undefined if
     * the `options.srcAddress` is not also set as it may not be broadcasted on all
     * interfaces as you might expect if the instance is also bound to `0.0.0.0` or `::`.
     *
     * If `options.srcAddress` is set, the packet will only be sent out via the corresponding
     * unicast socket.
     *
     * If `options.dstAddress` is set, the packet will be sent via unicast to the specified
     * address.
     *
     * If any failures are returned upon attempting to send, they will be returned as an array
     * of those errors.
     *
     * @param message
     * @param options
     * @throws Error if the specified `options.srcAddress` is not available
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

                if (!this.addresses.includes(options.srcAddress)) {
                    throw new Error(`Cannot use ${options.srcAddress} with multicast socket`);
                }

                this.multicastSocket.setMulticastInterface(options.srcAddress);
            }
        } else if (options.srcAddress) {
            if (typeof options.srcAddress !== 'string') {
                options.srcAddress = options.srcAddress.address.split('/')[0];
            }

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
     * Returns an array of objects containing the address information all the underlying sockets.
     *
     * For UDP sockets, each object will contain address, family, and port properties.
     */
    public get addressInfo (): AddressInfo[] {
        const result: AddressInfo[] = [this.multicastSocket.address()];

        for (const [, socket] of this.unicastSockets) {
            result.push(socket.address());
        }

        return result;
    }

    /**
     * Sets the TTL of the socket
     * @param ttl
     */
    public setTTL (ttl: number): void {
        this.multicastSocket.setTTL(ttl);
        this.multicastSocket.setMulticastTTL(ttl);
    }

    /**
     * Sets or clears the IP_MULTICAST_LOOP socket option. When set to true, our own multicast packets will also
     * be received on the local interface.
     * @param loopback
     */
    public setMulticastLoopback (loopback: boolean): void {
        this.options.loopback = loopback;

        this.multicastSocket.setMulticastLoopback(loopback);
    }

    /**
     * Close the underlying socket and stop listening for data on it. If a callback is provided, it
     * is added as a listener for the 'close' event.
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
     * Closes the underlying socket(s) and cleans all event listeners from the instance
     */
    public async destroy (): Promise<void> {
        try {
            await this.close();
        } finally {
            for (const [, socket] of this.unicastSockets) {
                socket.removeAllListeners();
            }

            this.multicastSocket.removeAllListeners();
        }
    }

    /**
     * By default, binding a socket will cause it to block the Node.js process from exiting as long
     * as the socket is open. The socket. unref() method can be used to exclude the socket from the
     * reference counting that keeps the Node.js process active. The socket ref() method adds the
     * socket back to the reference counting and restores the default behavior.
     */
    public ref (): void {
        for (const [, socket] of this.unicastSockets) {
            socket.ref();
        }

        this.multicastSocket.ref();
    }

    /**
     * By default, binding a socket will cause it to block the Node.js process from exiting as long
     * as the socket is open. The socket unref() method can be used to exclude the socket from the
     * reference counting that keeps the Node.js process active, allowing the process to exit even
     * if the socket is still listening
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
         * The local IPv4, IPv6, or interface name to which the multicast socket is bound.
         * If unspecified, the socket will listen to all available interfaces.
         *
         * Note: if the interface is an IPv4 or IPv6 address, the socket will only listen on
         * that interface. If the interface is an interface name, the socket will listen to
         * all addresses assigned to that interface.
         *
         * Note: if the interface is an IPv6 address, the socket will only listen on that
         * interface. If the interface is an interface name, the socket will listen to
         * all addresses assigned to that interface.
         */
        host?: string | Address4 | Address6;
        /**
         * When exclusive is set to false (the default), cluster workers will use the same underlying
         * socket handle allowing connection handling duties to be shared. When exclusive is true; however,
         * the handle is not shared and attempted port sharing results in an error. Creating a Socket
         * with the reusePort option set to true causes exclusive to always be true
         */
        exclusive?: boolean;
        /**
         * The multicast group address to join
         */
        multicastGroup: string;
        /**
         * When set to true, the instance will also receive outgoing multicast packets
         * @default false
         */
        loopback?: boolean;
    }

    export namespace Send {
        export type Options = {
            /**
             * If set, will send the packet via the multicast socket.
             * @default false
             */
            useMulticastSocket?: boolean;
            /**
             * The source address to use for the outgoing multicast packet.
             *
             * Note: if not specified, the packet is sent out of all the underlying
             * unicast sockets so long as `sendViaMulticast` is not specified.
             */
            srcAddress?: string | Address4 | Address6;
            /**
             * The unicast destination address to use for the outgoing packet.
             *
             * Note: if not specified, the packet is sent to the multicast address
             * specified in the constructor options.
             */
            dstAddress?: string | Address4 | Address6;
            /**
             * The destination port to use for the outgoing multicast packet.
             *
             * Note: if not specified, the packet is sent to the port specified in the
             * constructor options.
             */
            dstPort?: number;
        }
    }
}

export default MulticastSocket;
