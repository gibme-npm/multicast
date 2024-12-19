// Copyright (c) 2018-2024, Brandon Lehmann <brandonlehmann@gmail.com>
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

import { SocketOptions } from 'dgram';

export interface MulticastOptions extends Omit<SocketOptions, 'type'> {
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

export interface SendOptions {
    srcAddress?: string;
    dstAddress?: string;
    dstPort?: number;
}
