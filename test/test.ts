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

import { describe, it, before, after } from 'mocha';
import MulticastSocket from '../src';
import assert from 'assert';

describe('Unit Tests', async () => {
    let socket: MulticastSocket;
    const message = Buffer.from('This is a test message');

    before(async () => {
        socket = await MulticastSocket.create({
            port: 5959,
            multicastGroup: '224.0.0.251',
            loopback: true
        });
    });

    after(async () => {
        if (socket) {
            await socket.destroy();
        }
    });

    it('Has Addresses', () => {
        assert.notEqual(socket.addresses.length, 0);
    });

    it('Has Interfaces', () => {
        assert.notEqual(socket.interfaces.length, 0);
    });

    it('Has AddressInfo', () => {
        assert.notEqual(socket.addressInfo.length, 0);
    });

    it('setTTL()', () => {
        socket.setTTL(255);
    });

    it('setMulticastLoopback()', () => {
        socket.setMulticastLoopback(true);
    });

    it('ref()', () => {
        socket.ref();
    });

    it('unref()', () => {
        socket.unref();
    });

    it('Sends & Receives message', async function () {
        // eslint-disable-next-line @typescript-eslint/no-this-alias
        const $this = this;

        return new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
                return reject(new Error('Timeout waiting for multicast message'));
            }, 1000);

            socket.once('message', (rmessage, _rinfo, fromSelf) => {
                clearTimeout(timeout);
                if (rmessage.equals(message) && fromSelf) return resolve();
                return reject(new Error('Message did not match'));
            });

            socket.send(message).then(errors => {
                if (errors.length > 0) {
                    $this.skip();

                    return resolve();
                }
            });
        });
    });
});
