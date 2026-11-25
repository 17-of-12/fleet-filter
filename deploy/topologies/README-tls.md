# Certificate handling per topology

Only `edge-tls` and `behind-lb-tls` hold a certificate. `behind-lb-plain` must not be given one: the
balancer is the TLS endpoint and the gateway has nothing to terminate.

For both TLS profiles, renewal is the same mechanism:

```
certbot certonly --standalone -d gateway.example.edu     # once, on the host that owns :80
systemctl enable --now fleet-filter-gateway-cert.timer   # daily renew, no-op unless due
```

The deploy hook installs the material where the policy says the gateway reads it, reloads, and then
reads the served certificate back to prove the new one is in service - rolling back if it is not.
See `docs/CERTIFICATES.md`.

`behind-lb-tls` has two TLS legs and therefore two certificates that can expire: the balancer's for
clients, and this pool member's for the balancer. Both need a renewal path and a days-remaining
check. `bin/gateway-cert-status.sh` covers the second one.
