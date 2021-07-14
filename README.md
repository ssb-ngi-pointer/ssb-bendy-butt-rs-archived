# ssb-bendy-butt-rs

Bendy Butt (BB) metafeed format for Secure Scuttlebutt (SSB).

Based on the JavaScript reference implementation: [ssb-bendy-butt](https://github.com/ssb-ngi-pointer/ssb-bendy-butt) (written according to the [specification](https://github.com/ssb-ngi-pointer/bendy-butt-spec)).

## Data Types

Before a message can be encoded it must first be constructed using the provided data types. The top-level type, expected as input by the encoder, is a `Msg` `struct` (provided by this library). It is up to the library user to instantiate this type with the desired message data. All fields are required.

```rust
pub struct Msg {
    previous: String,
    author: String,
    sequence: i32,
    timestamp: i64,
    signature: String,
    content: Content,
}
```

`Content` is an `enum` with variants catering for a private message (encrypted `String` type) or a `FeedData` `struct`. These types must be instantiated before the construction of the top-level `Msg` type.

```rust
pub enum Content {
    // encrypted message (box2)
    Private(String),
    Feed(FeedData, String),
}

pub struct FeedData {
    feed_type: String,
    subfeed: String,
    metafeed: String,
    nonce: String,
    // WIP: more fields will be added here
}
```

## Encode

The encoder expects a message in the form of a `Msg` `struct` (defined above). The encoded value is returned as a Bencoded vector of bytes. Message fields (excluding `sequence` and `timestamp`) are encoded as BFE values before Bencoding.

## Decode

The decoder expects a message in the form of a byte vector (`Vec<u8>`). The decoded value is returned as a `Msg` `struct`.

## Documentation

Use `cargo doc` to generate and serve the Rust documentation for this library:

```bash
git clone git@github.com:ssb-ngi-pointer/ssb-bendy-butt-rs.git
cd ssb-bendy-butt-rs
cargo doc --no-deps --open
```

## License

LGPL-3.0.
