# Multisocket Socket Library

An abstract multicast socket library designed to handle some of the platform specific implementation details that
make it difficult to write a cross platform multicast socket library.

## Documentation

[https://gibme-npm.github.io/multicast](https://gibme-npm.github.io/multicast)

## Features

* IPv4 and IPv6 Support
* Windows, Linux, and Mac OS X Support
* Cross Platform
* Asynchronous
* Non-Blocking
* Supports Multicast and Unicast Messages
* Supports Joining and Leaving Multicast Groups
* Proper handling of listening on all interfaces
  * Creates a singular multicast socket for listening (or sending)
  * Creates a separate unicast socket for each interface for receiving unicast replies and/or sending messages (to ensure it goes out on all interfaces when bound to all)
* Ability to listen on one interface (by IP or name)
* Supports dynamic TTL
* Loopback support

## Sample Code

```typescript
import { MulticastSocket } from '@gibme/multicast';

(async () => {
    const socket = await MulticastSocket.create({
        port: 5959,
        multicastGroup: '224.0.0.251',
        loopback: true
    });
    
    socket.on('message', (message, remote, fromSelf) => {
        console.log({message, remote, fromSelf});
    })
    
    socket.send('Hello World');
});
```
