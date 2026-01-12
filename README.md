# wireguard-router

This is a proof of concept UDP-based router for wireguard packets.

It loads a list of "backend" peers from a config file.
Clients can use the router like they would the upstream backend, using the IP and port of the router.
This allows utilising the same IP and port for multiple peers.

The router does forwarding as follows:
- It looks up the mac1 value of the initial handshake packet to determine the backend it should route the session to.
  Since this value is computed using the public key of the server, the router needs to know the public key of each backend peer.
  It then stores the client peers server identity in order to facilitate further packet forwarding.
- On the handshake response, a reverse session link is established.

All sessions are stored in a HashMap. This may be contested in the future to improve performance.

Todo:
- Hot-reload config file to manage runtime updates to the backend peers
- Garbage collect old sessions, either when a peer is removed and also when they haven't seen packets for a while
- Metrics for different packet types
- Some architecture diagrams

