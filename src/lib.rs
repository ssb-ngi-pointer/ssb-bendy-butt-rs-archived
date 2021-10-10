// SPDX-FileCopyrightText: 2021 Andrew 'glyph' Reid
//
// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssb_bfe_rs::BfeValue;

/* ENCODED TYPES */

/// Represents a Bendy Butt message with BFE-encoded payload and signature.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct BendyMsg(BendyPayload, BfeValue);

/// Represents a Bendy Butt message payload with BFE-encoded values.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
// [ author, sequence, previous, timestamp, content ]
pub struct BendyPayload(BfeValue, i32, BfeValue, i64, BendyContent);

/// Represents the content payload variants of a BFE-encoded Bendy Butt message.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum BendyContent {
    Private(BfeValue),
    Feed(BfeValue, BfeValue),
}

/* DECODED TYPES */

/// Represents a decoded Bendy Butt message with payload fields and signature.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Msg {
    previous: String,
    author: String,
    sequence: i32,
    timestamp: i64,
    signature: String,
    content: Content,
}

/// Represents the content payload variants of a decoded Bendy Butt message.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum Content {
    // encrypted message (box2)
    Private(String),
    Feed(FeedData, String),
}

/// Represents the message content payload feed data of a decoded Bendy Butt message.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct FeedData {
    feed_type: String,
    subfeed: String,
    metafeed: String,
    nonce: String,
}

/// Take a message in the form of a `Msg` `struct`, encode the fields using the BFE encoding scheme
/// (excluding `sequence` and `timestamp`), then encode the whole message with Bencode and return
/// the bytes as a `Vec<u8>`.
pub fn encode(msg: &Msg) -> Result<Vec<u8>> {
    let content: BendyContent;
    match &msg.content {
        Content::Private(msg) => {
            let encoded_msg = ssb_bfe_rs::encode_box(msg)?;
            content = BendyContent::Private(BfeValue::Buffer(encoded_msg));
        }
        Content::Feed(data, sig) => {
            let encoded_data = ssb_bfe_rs::encode(&json!(data))?;
            let encoded_sig = ssb_bfe_rs::encode_sig(sig)?;
            content = BendyContent::Feed(encoded_data, BfeValue::Buffer(encoded_sig));
        }
    }

    let previous = BfeValue::Buffer(ssb_bfe_rs::encode_msg(&msg.previous)?);
    let author = BfeValue::Buffer(ssb_bfe_rs::encode_feed(&msg.author)?);
    let sequence = msg.sequence;
    let timestamp = msg.timestamp;
    let signature = BfeValue::Buffer(ssb_bfe_rs::encode_sig(&msg.signature)?);

    let payload = BendyPayload(author, sequence, previous, timestamp, content);
    let bendy_msg = BendyMsg(payload, signature);
    let bencoded_msg = bendy::serde::to_bytes(&bendy_msg)?;

    Ok(bencoded_msg)
}

/// Take a message in the form of a Bencoded byte vector, deserialize and decode the bytes to
/// extract the message field data, then decode the BFE values and return a `Msg` `struct`.
pub fn decode(bendy_msg: Vec<u8>) -> Result<Msg> {
    let BendyMsg(payload, signature) = bendy::serde::from_bytes(&bendy_msg)?;
    let BendyPayload(author, sequence, previous, timestamp, content_data) = payload;

    let content;

    match content_data {
        BendyContent::Private(msg) => {
            let decoded_msg = serde_json::from_value(ssb_bfe_rs::decode(&msg)?)?;
            content = Content::Private(decoded_msg);
        }
        BendyContent::Feed(data, sig) => {
            let feed_data: FeedData = serde_json::from_value(ssb_bfe_rs::decode(&data)?)?;
            let feed_sig = serde_json::from_value(ssb_bfe_rs::decode(&sig)?)?;
            content = Content::Feed(feed_data, feed_sig)
        }
    }

    let msg = Msg {
        previous: serde_json::from_value(ssb_bfe_rs::decode(&previous)?)?,
        author: serde_json::from_value(ssb_bfe_rs::decode(&author)?)?,
        sequence,
        timestamp,
        signature: serde_json::from_value(ssb_bfe_rs::decode(&signature)?)?,
        content,
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use crate::{decode, encode, Content, FeedData, Msg};
    use bendy::encoding::ToBencode;

    #[test]
    fn bencode_vector() {
        let my_data = vec!["hello", "world"];
        let encoded = my_data.to_bencode().unwrap();

        assert_eq!(b"l5:hello5:worlde", encoded.as_slice());
    }

    #[test]
    fn encode_then_decode_msg_with_encrypted_content() {
        let content = Content::Private(BOX2.to_string());

        let msg = Msg {
            previous: MSG.to_string(),
            author: FEED.to_string(),
            sequence: 2,
            timestamp: 1,
            content,
            signature: SIG.to_string(),
        };

        let encoded = encode(&msg);
        assert!(encoded.is_ok());
        let encoded_msg = encoded.unwrap();

        let decoded = decode(encoded_msg);
        assert!(decoded.is_ok());
        let decoded_msg = decoded.unwrap();

        assert_eq!(msg, decoded_msg);
    }

    #[test]
    fn encode_then_decode_msg_with_feed_content() {
        let feed_data = FeedData {
            feed_type: "metafeed/add".to_string(),
            subfeed: FEED.to_string(),
            metafeed: FEED.to_string(),
            nonce: NONCE.to_string(),
        };

        let feed_sig = FEED_SIG.to_string();

        let content = Content::Feed(feed_data, feed_sig);

        let msg = Msg {
            previous: MSG.to_string(),
            author: FEED.to_string(),
            sequence: 2,
            timestamp: 1,
            content,
            signature: SIG.to_string(),
        };

        let encoded = encode(&msg);
        assert!(encoded.is_ok());
        let encoded_msg = encoded.unwrap();

        let decoded = decode(encoded_msg);
        assert!(decoded.is_ok());
        let decoded_msg = decoded.unwrap();

        assert_eq!(msg, decoded_msg);
    }

    const NONCE: &str = "Kvgsd74a1BJbeUlxsuCjzkEKm8IuQ/IBWNkUgNiu1Mc=";
    const MSG: &str = "%H3MlLmVPVgHU6rBSzautUBZibDttkI+cU4lAFUIM8Ag=.bbmsg-v1";
    const FEED: &str = "@6CAxOI3f+LUOVrbAl0IemqiS7ATpQvr9Mdw9LC4+Uv0=.bbfeed-v1";
    const FEED_SIG: &str = "K1PgBYX64NUB6bBzcfu4BPEJtjl/Y+PZx7h/y94k6OjqCR9dIHXzjdiM4P7terusbSO464spYjz/LwvP4nqzAg==.sig.ed25519";
    const SIG: &str = "F/XZ1uOwXNLKSHynxIvV/FUW1Fd9hIqxJw8TgTbMlf39SbVTwdRPdgxZxp9DoaMIj2yEfm14O0L9kcQJCIW2Cg==.sig.ed25519";
    const BOX2: &str = "WQyfhDDHQ1gH34uppHbj8SldRu8hD2764gQ6TAhaVp6R01EMBnJQj5ewD5F+UT5NwvV91uU8q5XCjuvcP4ihCJ0RtX8HjKyN+tDKP5gKB3UZo/eO/rP5CcPGoIG7pcLBsd3DQbZLfTnb/iqECEji9gclNcGENTS2u6aATwbQ4uQ7RzIAKKT2NfC2qk86p/gXC2owDFAazuPlQTT8DMNvO8G52gb48a75CGKsDAevrC//Bz38VFxwUiTKzRWaxCbTK9knj39u3qoCP9VLyyRqITgNwvlGLP7ndchTyBiO0TPNkb9PAOenw5WBjyWhA61hpG+VkKpkaysBVGjXYv8OpV1HGbs87TI79uT7JrNV4wEZiwqGknwmCi5B2gbd7tav8yDXsK5yQgDncHQjZotsBFX2adP7Jli9WmvV3xX5lL3kBNKV0ZiE/DZUgB2m1OXvCjNI4fuZhnpZpEQi9coO+icrirKiH/UA8TS9HI72cIbkEJVxOTnKnsgr3Qc/5HhtRS17a54ymVmBsnpP+KqqCqKLN50TInb7qoUlvQ2nw07xX3Ig9usLb8Ik8U8XMb6SLqACxlZN/qW4EJzxVetoIk84AU1yLInK6v9dzfsewRYBXW8+lYbyxVNuIIK4pKYsx2WbjuJyZHgjgbCdGf/kjqP5rDs4zwqj2lmkO70PoEUrcSi46J2hkqtcrd1yl+F3/BDwFlxAXH+x4+LhmT7g+BSgzRUbWvCyeB+HJaoao6g4K/Fs8HxnbVB1zW761OQJaQnV86ZThkvUjXh2SEBlBd+D94eUCqIJkjI7RLt+D/0gxg/D7u1Zq14UxRijZryB51An7GdXtEc2xhU+Bh/aPmKmMZ9D/ArdglSlnVUD8OIBVVw5jtooGlhxbOFHM4N5SoAO/yWPcbcuQz7t4SPij358rY574DLBGZEPCrS6KPpnrlqlnZK4f6/+9zv3hfzNTXVvJtxZL/rvmNvbgh7LpMnSqjnsXqm86a3GXeVWD83TdCnL1oPqEi/8RItTrjy01DmVhUoV6t12STP4mHb8RjR+/ks+7lowfV3HQ13n6if0g0/u+Bzv6XXOX6iePPOHA3lFv2MSPKf9JZ0uQiqajR03YkNE8YnSTYu0Io1cGPZ/lWBp2tyWtwFmGtqw/9+O165tJhrdU2EXJ4T/XP136WpLD2+vtYsx3Xr5lfeD12/g+I/6jwduqTuHpst2tqvcSWoZ4DAWcpcKJ1mUbJU3/mLAYGwWb3XuqMOgJOLoztAwd5xFzUZD1MnR/iyYoZ2weYTSOz3OKR3cJyCjxBhIGaX5xpAc61K1dXNfERBJr9TS0mL2578dd5AauE6Ksn6YlGxNJIVC3VpdAtRbVHNX1g==.box2";
}
