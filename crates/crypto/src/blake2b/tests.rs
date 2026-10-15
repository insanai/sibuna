use super::*;
use crate::test_util::{XorShift, hex};
use std::string::ToString;

/// Hashes `data` in one piece with a fresh hasher for `output_len` bytes.
fn digest(params: &Params<'_>, data: &[u8]) -> std::vec::Vec<u8> {
    let mut hasher = Blake2b::with_params(params).unwrap();
    hasher.update(data);
    let mut out = std::vec![0u8; params.output_len];
    hasher.finalize_into(&mut out).unwrap();
    out
}

/// Hashes the concatenation of `pieces`, one `update` per piece.
fn digest_pieces(params: &Params<'_>, pieces: &[&[u8]]) -> std::vec::Vec<u8> {
    let mut hasher = Blake2b::with_params(params).unwrap();
    for piece in pieces {
        hasher.update(piece);
    }
    let mut out = std::vec![0u8; params.output_len];
    hasher.finalize_into(&mut out).unwrap();
    out
}

fn sized(output_len: usize) -> Params<'static> {
    Params { output_len, ..Default::default() }
}

const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// `"a" ** 64 ++ "b" ** 64` of the Zig tests: exactly one block.
fn a64_b64() -> std::vec::Vec<u8> {
    [[b'a'; 64], [b'b'; 64]].concat()
}

/// Zig's tests "blake2b160 single", "blake2b384 single" and "blake2b512 single".
#[test]
fn zig_single() {
    let cases: [(usize, [&str; 4]); 3] = [
        (
            20,
            [
                "3345524abf6bbe1809449224b5972c41790b6cf2",
                "384264f676f39536840523f284921cdc68b6846b",
                "3c523ed102ab45a37d54f5610d5a983162fde84f",
                "43758f5de1740f651f1ae39de92260fe8bd5a11f",
            ],
        ),
        (
            48,
            [
                "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324\
                 4a6caf0498812673c5e05ef583825100",
                "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6\
                 c66ba83be64b302d7cba6ce15bb556f4",
                "b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc\
                 8018f6ed9e2906720c8d2a3aeda9c03d",
                "b7283f0172fecbbd7eca32ce10d8a6c06b453cb3cf675b33eb4246f0da2bb94a\
                 6c0bdd6eec0b5fd71ec4fd51be80bf4c",
            ],
        ),
        (
            64,
            [
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
                 d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                 7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673\
                 f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
                "049980af04d6a2cf16b4b49793c3ed7e40732073788806f2c989ebe9547bda05\
                 41d63abe298ec8955d08af48ae731f2e8a0bd6d201655a5473b4aa79d211b920",
            ],
        ),
    ];
    let long = a64_b64();
    for (output_len, expected) in cases {
        let inputs: [&[u8]; 4] = [b"", b"abc", FOX, &long];
        for (input, want) in inputs.iter().zip(expected) {
            assert_eq!(digest(&sized(output_len), input), hex(want), "{output_len} bytes");
        }
    }
}

/// Zig's "streaming" tests: pieces, including the salt and context (personalisation)
/// variant.
#[test]
fn zig_streaming() {
    let salted = |output_len| Params {
        output_len,
        salt: [0x42; 16],
        personal: [0x69; 16],
        ..Default::default()
    };
    let cases = [
        (
            20,
            "384264f676f39536840523f284921cdc68b6846b",
            "72328f8a8200663752fc302d372b5dd9b49dd8dc",
        ),
        (
            48,
            "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6\
             c66ba83be64b302d7cba6ce15bb556f4",
            "934c48fcb197031c71f583d92f98703510805e72142e0b46f5752d1e971bc86c\
             355d556035613ff7a4154b4de09dac5c",
        ),
    ];
    let long = a64_b64();
    for (output_len, abc, salted_digest) in cases {
        let params = sized(output_len);
        assert_eq!(digest_pieces(&params, &[b"a", b"b", b"c"]), hex(abc));
        assert_eq!(digest_pieces(&params, &[&[b'a'; 64], &[b'b'; 64]]), digest(&params, &long));
        let params = salted(output_len);
        assert_eq!(digest_pieces(&params, &[&[b'a'; 64], &[b'b'; 64]]), hex(salted_digest));
    }
}

/// Zig's "blake2b512 keyed".
#[test]
fn zig_keyed() {
    let expected = hex("8a978060ccaf582f388f37454363071ac9a67e3a704585fd879fb8a419a447e3\
         89c7c6de790faa20a7a7dccf197de736bc5b40b98a930b36df5bee7555750c4d");
    let params = Params { key: b"secret_key", ..Default::default() };
    assert_eq!(digest(&params, &a64_b64()), expected);
    assert_eq!(digest_pieces(&params, &[&[b'a'; 64], &[b'b'; 64]]), expected);
    let mut out = [0u8; 64];
    keyed_hash_into(b"secret_key", &mut out, &a64_b64()).unwrap();
    assert_eq!(out.as_slice(), expected);
}

/// Zig's "comptime" tests: one zero block.
#[test]
fn zig_zero_block() {
    let block = [0u8; BLOCK_LEN];
    assert_eq!(digest(&sized(20), &block), hex("8d26f158f564e3293b42f5e3d34263cb173aa9c9"));
    assert_eq!(
        digest(&sized(48), &block),
        hex("e8aa1931ea0422e4446fecdd25c16cf35c240b10cb4659dd5c776eddcaa4d922\
             397a589404b46eb2e53d78132d05fd7d")
    );
    assert_eq!(
        hash(&block).as_slice(),
        hex("865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf7\
             98e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41")
    );
}

/// The inputs of the generated vectors, identified by their lengths.
fn input_of_len(len: usize) -> std::vec::Vec<u8> {
    match len {
        0 => std::vec::Vec::new(),
        3 => b"abc".to_vec(),
        43 => FOX.to_vec(),
        127..=129 => std::vec![b'a'; len],
        300 => std::vec![b'b'; 300],
        _ => panic!("no generated input of length {len}"),
    }
}

#[test]
fn zig_variable_output_lengths() {
    for (input_len, output_len, expected) in VARIABLE {
        let input = input_of_len(input_len);
        assert_eq!(digest(&sized(output_len), &input), hex(expected), "{input_len}/{output_len}");
        let mut out = std::vec![0u8; output_len];
        hash_into(&mut out, &input).unwrap();
        assert_eq!(out, hex(expected));
    }
}

#[test]
fn zig_keyed_lengths() {
    let key: [u8; 64] = core::array::from_fn(|i| i as u8);
    for (input_len, key_len, expected) in KEYED {
        let input = input_of_len(input_len);
        let params = Params { key: &key[..key_len], ..Default::default() };
        assert_eq!(digest(&params, &input), hex(expected), "{input_len}/{key_len}");
    }
}

#[test]
fn rejects_invalid_lengths() {
    assert_eq!(Blake2b::new(0).unwrap_err(), Error::InvalidOutputLength);
    assert_eq!(Blake2b::new(65).unwrap_err(), Error::InvalidOutputLength);
    assert_eq!(Blake2b::new_keyed(&[0; 65], 32).unwrap_err(), Error::InvalidKeyLength);
    assert!(Blake2b::new_keyed(&[0; 64], 64).is_ok());
    let mut out = [0u8; 31];
    assert_eq!(Blake2b::new(32).unwrap().finalize_into(&mut out), Err(Error::InvalidOutputLength));
    assert_eq!(Blake2b::new(32).unwrap().finalize(), Err(Error::InvalidOutputLength));
    assert_eq!(hash_into(&mut [], b""), Err(Error::InvalidOutputLength));
    assert_eq!(Error::InvalidKeyLength.to_string(), "BLAKE2b key must be at most 64 bytes");
}

/// Any split of the input into pieces gives the one-shot digest.
#[test]
fn streaming_matches_one_shot() {
    let mut rng = XorShift::new(0xb1a6e2b);
    let mut data = std::vec![0u8; 1000];
    rng.fill(&mut data);
    for _ in 0..500 {
        let len = rng.below(data.len() + 1);
        let output_len = 1 + rng.below(64);
        let key_len = if rng.below(3) == 0 { 0 } else { rng.below(65) };
        let params = Params { output_len, key: &data[..key_len], ..Default::default() };
        let expected = digest(&params, &data[..len]);
        let mut hasher = Blake2b::with_params(&params).unwrap();
        let mut rest = &data[..len];
        while !rest.is_empty() {
            let take = rng.below(rest.len().min(300) + 1);
            hasher.update(&rest[..take]);
            rest = &rest[take..];
        }
        let mut out = std::vec![0u8; output_len];
        hasher.finalize_into(&mut out).unwrap();
        assert_eq!(out, expected);
    }
}

/// Generated with Zig 0.16 `Blake2b512.init(.{ .expected_out_bits = 8 * len })`: input length,
/// output length, digest. The inputs are those of [`input_of_len`].
const VARIABLE: [(usize, usize, &str); 49] = [
    (0, 1, "2e"),
    (0, 16, "cae66941d9efbd404e4d88758ea67670"),
    (0, 20, "3345524abf6bbe1809449224b5972c41790b6cf2"),
    (0, 32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
    (
        0,
        48,
        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd324\
         4a6caf0498812673c5e05ef583825100",
    ),
    (
        0,
        63,
        "4ded8c5fc8b12f3273f877ca585a44ad6503249a2b345d6d9c0e67d85bcb700d\
         b4178c0303e93b8f4ad758b8e2c9fd8b3d0c28e585f1928334bb77d36782e8",
    ),
    (
        0,
        64,
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ),
    (3, 1, "6b"),
    (3, 16, "cf4ab791c62b8d2b2109c90275287816"),
    (3, 20, "384264f676f39536840523f284921cdc68b6846b"),
    (3, 32, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
    (
        3,
        48,
        "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6\
         c66ba83be64b302d7cba6ce15bb556f4",
    ),
    (
        3,
        63,
        "eb5324bb0b0f9ca27381f22f5e49604d7c341b77371fe5bf61fb643c8ab481c7\
         555ef17c9b9e7c92f0daafff6c0d748cab97d2b267bf53f8225c173ea26f3e",
    ),
    (
        3,
        64,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ),
    (43, 1, "b5"),
    (43, 16, "249df9a49f517ddcd37f5c897620ec73"),
    (43, 20, "3c523ed102ab45a37d54f5610d5a983162fde84f"),
    (43, 32, "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9"),
    (
        43,
        48,
        "b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc\
         8018f6ed9e2906720c8d2a3aeda9c03d",
    ),
    (
        43,
        63,
        "549fb130c7c7c830e402b873706b678ef839a648dca98b3d17b82716ab8409d7\
         2b74d3a2e4767fbdd58b9d9fabcdcf4d58f472b59835fa30a5362f3429bccd",
    ),
    (
        43,
        64,
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673\
         f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
    ),
    (127, 1, "94"),
    (127, 16, "2228006d5107a5239e500da574466288"),
    (127, 20, "202dc3632e9c720602f415b06b39ef0aa9ef26ab"),
    (127, 32, "59e2f1aba240f20aa591016f5ef429990bc9c2131dcd0d30f0ffd75ed18f317d"),
    (
        127,
        48,
        "88aa2c54f0f60e26a2619288a110e3f45b56f0eb31ae78f50b79a283678634d0\
         eff091aa02c79aaa3751848e3cf35e9a",
    ),
    (
        127,
        63,
        "07ba8e7b658cff3cf0f59b402a136d59bb382bbead3954c0fbe366d39933c3a2\
         3486b64a90e92f808afd3b4689f1c5aa212749c290462cf9213fffead955ac",
    ),
    (
        127,
        64,
        "94596b9d6199c807c40ae1a935f3633ba5a8dd5655f7f1bd44f5285b1ce8dbb0\
         054771eba409539df85a963296d28788807105153c90fa3ec3d761228e90f8b8",
    ),
    (128, 1, "3a"),
    (128, 16, "1271d28e731afb57bdfba6bdaf3501be"),
    (128, 20, "353a80c4a604c3e7897991a345a45133f80c4a55"),
    (128, 32, "ae2aa48507885c4c950fb809b2076f959cde9f8ea6da260d9a3587df33dac450"),
    (
        128,
        48,
        "0bd02bbca199ec748b5d3e391dee4594c9ce78541af3e4798d2aa5ed00cce7bc\
         70027606cd3cd8daf44dafd15a3566db",
    ),
    (
        128,
        63,
        "87244ab6dec44abdb8ab9b5ca4310c49251d9f3e835d13454b917efd964acf45\
         ab9f5cf3ed38fdd6adae7925435d1f3026c9f6cf4b27993c95c59882559143",
    ),
    (
        128,
        64,
        "fc6c71f688f43ea7d60817478808f3cac753e61571865c95adbc2d9122c943a7\
         6b92c2cb1047ef3fe7bf6e436ec1d0a99a9e5b216780bf7fed9d7ca91d3a8f3b",
    ),
    (129, 1, "cb"),
    (129, 16, "68b7bafbad5055c4ebe6eb170a0f8524"),
    (129, 20, "eeff408d65ecf3235b2586586d331fea9014b8d8"),
    (129, 32, "2f64744a6de0d2c0b56e64cf6e29a5aaa255010d415d51c75ccc82f73dccd865"),
    (
        129,
        48,
        "d7a9fb931381834c12884bca2b81e183dc6a2e3f8633c9f0c9622cee4c7c725b\
         688f30a62189129f2329bf9d11172360",
    ),
    (
        129,
        63,
        "61fa26dadab00e07375fbbca7a9667b7d7009a7473c88220eb962449ec882526\
         99ff9c3d548f4c41c86ccc7e1d4332149b28e5c8f2612818a282e5fd62bd25",
    ),
    (
        129,
        64,
        "55e6e0eb418149a8af92fd9ddc99254781b2f522a131b4f4d984404b71a00e11\
         67b8124d5dcddd4c6977b299392335d6edd303da6d344d74bbef2d38101b232b",
    ),
    (300, 1, "17"),
    (300, 16, "0bed2e72cb9260b5a67c3fd45a3ba6cf"),
    (300, 20, "13e01b74984a53cb3a9b6671d455d628d28171ba"),
    (300, 32, "4eaf929704b058a3ff42093ee9d3c8dff9615a14301636b6be746a0e97c2d37e"),
    (
        300,
        48,
        "b9266db8ea566f965007e6631b1ab258af790233b5f2d27bc19bc8433d0634a8\
         ca12f810f17b83cdb8fc3ddf7280d8f3",
    ),
    (
        300,
        63,
        "fbb5e9b2e6bd5b7877aae29c31b535d1bf79aa5e2011a7cf6e9301a5f0050174\
         0e7a2bf5fb3af0a20f7f38e893724eb26f54b900b70b2806beeff6e5e0edda",
    ),
    (
        300,
        64,
        "dbea7d2e0eceee394d414e48767c42b78905eab759151039c83ec8a6f435a8e8\
         72850b73e95f32913ea6f249daf05e2ba559a0ea1a3957e55d12d035fca87eed",
    ),
];

/// Generated with Zig 0.16 `Blake2b512.init(.{ .key = key[0..key_len] })` where key byte
/// `i` is `i`: input length, key length, digest.
const KEYED: [(usize, usize, &str); 21] = [
    (
        0,
        1,
        "aaf42280524929171e417e77be67f9edec3a8461bbe7b5c2bd1d9a3d0928f1db\
         bd1f6600bb866b72f0e3b3e22282c145f69873a3d250ddc43c423685d1247657",
    ),
    (
        0,
        32,
        "84bfa69f0d90df7db2a3ee026042988b5bd9caa2320af1f371823dd28351202f\
         8e6277c40c050711c8dd4e2c1ac30c34c9aed0bddd468b031287fe872675e0cc",
    ),
    (
        0,
        64,
        "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786\
         b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
    ),
    (
        3,
        1,
        "7cfcb59f70977f0811a0a8dab92faa051dedea2b21bf0623cad03e62ae08d8f6\
         9c3e475a988b4e829869d03016113383198e94fb1feeb76a181018ca0463c413",
    ),
    (
        3,
        32,
        "9af0244b7da7fe29d90a89727e06a0c93977ce1ad7edcb76ac0b24142194ea00\
         c77be4a1d3fededd31d5a593625a508e742fc90d708f8b48a5c246e4e8e42d94",
    ),
    (
        3,
        64,
        "06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579e\
         d590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51",
    ),
    (
        43,
        1,
        "87ac47758b7d75777fe49d573c62ebc163ac4a95bc38639e1fa6154a3fecc24e\
         85cf4745df72a70a4ed285c6c965ae9c2c2d82f98030c7d1f20e5157841ca641",
    ),
    (
        43,
        32,
        "a44a52374dc66f94c213e25b2ee5b055c8aae43f17d975726c2452f5c2516504\
         db62be4ccf58525f5dfc6819001a7c9a74400cc53897744e72407642f71e2bee",
    ),
    (
        43,
        64,
        "1d58d71414d24752db3274afdc483fc0f4c68317c4c2f6a31e09de9437ba02cc\
         ab8c8585790a52b0d476f7920c0e1397d1aec9e52f3df3feae76f7d6223ce5cf",
    ),
    (
        127,
        1,
        "fc27336636fd1bf4ce8a822f3dc3ef26bbe449c261fb58b245c34579139c1907\
         8d8311a567d89aefa865ccfb684fd1f0213898860ba08040381e42e2f869744f",
    ),
    (
        127,
        32,
        "2b0d90900e4640fe69881812637678c07a99374db968dc6b9f3e25710c2c71a7\
         7e6bf5427be4aa539aef83aac31194dd7057e231bd074bf52047ba3128dbb773",
    ),
    (
        127,
        64,
        "ae553100e0936aaea9a7c05a7d031079916bdcbc34df9eb72dbb62aa306a6ccd\
         24aabaa58da0de3df8fd040ef4f2369312a36a40020661ee719f5bdcc540af53",
    ),
    (
        128,
        1,
        "e053c3b3ccee7017deb1341022723584b6b78e0414d1470c9c216642b59e1f60\
         358ac5be50e86ca2a3f7e5e51022deb759c3db3f13549bc87cebd7951a90be7d",
    ),
    (
        128,
        32,
        "6239a8ab9e3b95bb4e4598effbdbb3293d204c184340561c2853649b931c385a\
         bd4e4c8679e9f9701ad479f274ac6f26babc573d49488e87788e52391e387e42",
    ),
    (
        128,
        64,
        "9792d5d15fd64e3604791412c384bd664158fd0d4d91f9798201ac1b71108e47\
         62baf64472d6a682b2a40e51133b570e2379e0654a4e2c2ffe6c4240c123a87c",
    ),
    (
        129,
        1,
        "f0e63a66d40694020a3d9021620b54f9f6c52c8bbe3110c8a13c02bcbe3f7a76\
         666afd9dff7f2e9dfa74866b431a64295b222d72e66dae7e8cc8020d2640f3de",
    ),
    (
        129,
        32,
        "96ea71414eb923ec3ed80cf11c1102362f8783896da6753fedc78be196b706b3\
         6700a67aaff3e462356bbfdd169acfbdf38974d9574551a375526025b973647c",
    ),
    (
        129,
        64,
        "c0b04732f10038e2d65f65f9d1d99ce8c8116061b852b8e9b94206b9e1b4761e\
         fcea555a35d753d480619d665042a196103880a3f70949989a725d5827242f3c",
    ),
    (
        300,
        1,
        "9357fa184b94faf62dcb09bbf57e8a01b168f2b6a81383d42c9ed3847ff53791\
         92a6c92aa4022d8b2bbf72c0b73d330c5b010f9641fbce8b0492d3ee9bdc53f9",
    ),
    (
        300,
        32,
        "920f9d303efa54608785c32a813f2b32b83db5e664a50d19f74f0d0ac4bf56a1\
         0204d53a818d00262c067a8ee90e3531d5d28659b136d8bd434accc750c88ea2",
    ),
    (
        300,
        64,
        "d318684b38deff0328b8a27ea8c33246502346c206df72b07cae5dc25fbf3ee6\
         4c7aabbf5afc9e571ff10676a96fe86d6b819dd3a6e35aaa9ae90d0247f1eb64",
    ),
];
