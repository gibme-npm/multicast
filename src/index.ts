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

import { createSocket, RemoteInfo, Socket, SocketType, SocketOptions } from 'dgram';
import { AddressInfo } from 'net';
import { EventEmitter } from 'events';
import { detect_type, compare_IP_addresses, get_addresses, is_valid_ip } from './helpers';

export class MulticastSocket extends EventEmitter {
    private readonly socket: Socket;
    private readonly type: SocketType;

    /**
     * Creates a new multicast socket using the supplied options.
     *
     * When creating an instance, the underlying socket is created, the events mapped
     * through to the instance of this class, the socket is bound, and we're off to the races.
     *
     * Note: the socket type (udp4 or udp6) is automatically detected based upon
     * the type of `multicastAddress` supplied in the constructor options.
     *
     * Additionally, the `interface` supplied can be one of an IPv4, IPv6, interface name, or undefined.
     *
     * If `interface` is undefined, we will listen on all available interfaces
     *      (similar to binding to `0.0.0.0` or `::`)
     *
     * If `interface` is an interface name, we will listen on all addresses assigned to that interface
     *
     * @param multicastOptions
     */
    constructor (private readonly multicastOptions: MulticastSocket.Options) {
        super();

        this.multicastOptions.reuseAddr ??= true;

        this.type = detect_type(this.multicastOptions.multicastAddress);

        // build the list of interface addresses
        this._multicastInterfaces = (() => {
            const addresses = get_addresses(this.type);

            // if not set, then assume all
            if (!this.multicastOptions.address) return addresses;

            // check to see if the interface specified is an ip address
            if (is_valid_ip(this.multicastOptions.address)) {
                // confirm that the interface address type matches the multicast address type
                if (detect_type(this.multicastOptions.address) !== this.type) {
                    throw new Error('Interface address type does not match multicast address type');
                }

                // confirm that the interface address specified is actually on this system
                if (!addresses.includes(this.multicastOptions.address)) {
                    throw new Error(`Cannot use ${this.multicastOptions.address} for multicast`);
                }

                // if we made it this far, then it's a valid address that we can use
                return [this.multicastOptions.address];
            }

            // if it wasn't a valid address, then it 'must' be an interface name
            return get_addresses(this.type, this.multicastOptions.address);
        })().sort(compare_IP_addresses);

        // if we didn't find a list of usable interfaces, bail
        if (this._multicastInterfaces.length === 0) {
            throw new Error('No usable interfaces found');
        }

        this.socket = createSocket({ ...this.multicastOptions, type: this.type });
        this.socket.on('message', (message: Buffer, rinfo: RemoteInfo) =>
            this.emit('message', message, rinfo, this.multicastInterfaces.includes(rinfo.address)));
        this.socket.on('close', () => this.emit('close'));
        this.socket.on('connect', () => this.emit('connect'));
        this.socket.on('error', error => this.emit('error', error));
        this.socket.on('listening', () => this.emit('listening'));

        this.once('listening', () => {
            this.setTTL(255);
            this.setMulticastLoopback(this.multicastOptions.loopback ?? false);

            // default the outgoing interface to the lowest address found
            this.setMulticastInterface(this._multicastInterfaces[0]);

            // add the multicast membership for all the found interfaces
            for (const address of this._multicastInterfaces) {
                if (!this.addMembership(this.multicastOptions.multicastAddress, address)) {
                    this._multicastInterfaces = this._multicastInterfaces.filter(addr => addr !== address);
                }
            }
        });

        // bind the socket
        this.socket.bind({
            port: this.multicastOptions.port,
            address: this.type === 'udp4' ? '0.0.0.0' : '::',
            exclusive: this.multicastOptions.exclusive ?? false
        });
    }

    private _multicastInterfaces: string[] = [];

    /**
     * Returns the list of interfaces that have joined the multicast address of the socket
     */
    public get multicastInterfaces (): string[] {
        return this._multicastInterfaces;
    }

    private _multicastInterface?: string;

    /**
     * Returns the current outgoing multicast interface address
     */
    public get multicastInterface (): string | undefined {
        return this._multicastInterface;
    }

    /**
     * Sends the specified message via the socket
     *
     * Note: If a `srcAddress` is specified, we will attempt to change the multicast
     * outgoing interface to that interface; otherwise, we will use whatever outgoing
     * interface was last used
     * @param message
     * @param options
     */
    public async send (
        message: Buffer,
        options: MulticastSocket.Send.Options = {}
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            if (options.srcAddress) {
                try {
                    this.setMulticastInterface(options.srcAddress);
                } catch (error) {
                    return reject(error);
                }
            }

            options.dstAddress ??= this.multicastOptions.multicastAddress;
            options.dstPort ??= this.multicastOptions.port;

            this.socket.send(message,
                options.dstPort,
                options.dstAddress,
                error => {
                    if (error) return reject(error);

                    return resolve();
                });
        });
    }

    /**
     * Returns an object containing the address information for a socket. For UDP sockets, this object
     * will contain address, family, and port properties.
     */
    public address (): AddressInfo {
        return this.socket.address();
    }

    /**
     * Sets the TTL of the socket
     * @param ttl
     */
    public setTTL (ttl: number): void {
        this.socket.setTTL(ttl);
        this.socket.setMulticastTTL(ttl);
    }

    /**
     * Sets or clears the IP_MULTICAST_LOOP socket option. When set to true, multicast packets will also
     * be received on the local interface.
     * @param loopback
     */
    public setMulticastLoopback (loopback: boolean): void {
        this.socket.setMulticastLoopback(loopback);
    }

    /**
     * Changes the outgoing multicast interface
     * @param address
     * @throws
     */
    public setMulticastInterface (address: string): void {
        const addresses = get_addresses(this.type);

        if (!addresses.includes(address)) throw new Error(`Cannot use ${address} for multicast`);

        this.socket.setMulticastInterface(address);

        this._multicastInterface = address;
    }

    /**
     * Close the underlying socket and stop listening for data on it. If a callback is provided, it
     * is added as a listener for the 'close' event.
     */
    public close (): void {
        this.socket.close();
    }

    /**
     * By default, binding a socket will cause it to block the Node.js process from exiting as long
     * as the socket is open. The socket. unref() method can be used to exclude the socket from the
     * reference counting that keeps the Node.js process active. The socket ref() method adds the
     * socket back to the reference counting and restores the default behavior.
     */
    public ref (): void {
        this.socket.ref();
    }

    /**
     * By default, binding a socket will cause it to block the Node.js process from exiting as long
     * as the socket is open. The socket unref() method can be used to exclude the socket from the
     * reference counting that keeps the Node.js process active, allowing the process to exit even
     * if the socket is still listening
     */
    public unref (): void {
        this.socket.unref();
    }

    /**
     * Adds the specified interface address to the multicast address group
     * @param multicastAddress
     * @param interfaceAddress
     * @private
     */
    private addMembership (multicastAddress: string, interfaceAddress: string): boolean {
        try {
            this.socket.addMembership(multicastAddress, interfaceAddress);

            return true;
        } catch {
            return false;
        }
    }
}

export namespace MulticastSocket {
    export type Options = Omit<SocketOptions, 'type'> & {
        port: number;
        /**
         * The local IPv4, IPv6, or interface name to use with the socket
         */
        address?: string;
        /**
         * When exclusive is set to false (the default), cluster workers will use the same underlying
         * socket handle allowing connection handling duties to be shared. When exclusive is true; however,
         * the handle is not shared and attempted port sharing results in an error. Creating a Socket
         * with the reusePort option set to true causes exclusive to always be true
         */
        exclusive?: boolean;
        /**
         * The multicast group to join
         */
        multicastAddress: string;
        /**
         * When set to true, outgoing multicast packets will also be received by the instance
         */
        loopback?: boolean;
    }

    export namespace Send {
        export type Options = {
            srcAddress?: string;
            dstAddress?: string;
            dstPort?: number;
        }
    }
}

export default MulticastSocket;
