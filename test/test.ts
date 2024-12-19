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

import { describe, it, before, after } from 'mocha';
import MulticastSocket from '../src';

describe('Unit Tests', async () => {
    let socket: MulticastSocket;
    const message = Buffer.from('This is a test message');

    before(() => {
        socket = new MulticastSocket({
            port: 5959,
            multicastAddress: '224.0.0.251',
            loopback: true
        });
    });

    after(() => {
        if (socket) {
            socket.close();
        }
    });

    it('Sends & Receives message', async () => {
        return new Promise<void>((resolve, reject) => {
            socket.once('message', (rmessage, rinfo, fromSelf) => {
                if (rmessage.equals(message) && fromSelf) return resolve();
                return reject(new Error('Message did not match'));
            });

            socket.send(message).catch(error => reject(error));
        });
    });
});
