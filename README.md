# casita
`casita` is a Rust crate for talking to a Lutron Caseta device or other similar Lutron device which supports the LEAP protocol.

## What's Included?

This crate provides a program for extracting TLS certificates for the LEAP server by proving physical access (`get_certs`), a program for testing that those TLS certificates are valid and can be used to talk LEAP, and a library for communicating with LEAP servers like Caseta. The client is completely async and relies on `tokio` for spinning up tasks for handling reads, writes, and keep-alives. The client can detect via timeout when it loses connection to the server and it seems to not crash the program when that happens.

I'm planning to model LEAP messages in this crate and make it possible to easily serialize/deserialize these messages into JSON with `serde_json`. I do not plan to add abstractions for devices or APIs which abstract LEAP transactions in order to keep the API relatively simple. So that means request/response matching and the like are left completely up to the user.

## Acknowledgements

I based my implementation of `get_certs.rs` off of the equivalent code in [`pylutron_caseta`](https://github.com/gurumitts/pylutron-caseta) along with some heavy experimentation around the `openssl` APIs which are not so well documented for Rust. If you are looking for a higher-level API or are more fluent in python, I suggest you check out `pylutron_caseta`, it's well-written and worked very well for me until I got fed up with async in python.
