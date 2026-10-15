use super::*;
use crate::test_util::{hex, pattern};

/// One case of the official BLAKE3 test vectors (`test_vectors.json` of the reference
/// repository): the input is `input_len` bytes of the pattern `i % 251`, and every output
/// is 131 bytes of extended output. The expected values were produced with Zig 0.16
/// `std.crypto.hash.Blake3` and agree with the published file where we checked them.
struct Vector {
    input_len: usize,
    hash: &'static str,
    keyed_hash: &'static str,
    derive_key: &'static str,
}

const KEY: &[u8; KEY_LEN] = b"whats the Elvish word for friend";
const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

const VECTORS: &[Vector] = &[
    Vector {
        input_len: 0,
        hash: "\
            af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b\
            7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b\
            92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e7636\
            99a31c5363165421cce14d",
        keyed_hash: "\
            92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94\
            822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f543\
            72df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a\
            9210694254c371e851bc8f",
        derive_key: "\
            2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfc\
            f3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d596492\
            57cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547\
            dfd3aa1a035ba6689d89a0",
    },
    Vector {
        input_len: 1,
        hash: "\
            2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20c\
            db535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3\
            b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba13\
            1e5f1351f3f1da786545e5",
        keyed_hash: "\
            6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c04906094130\
            06fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c4e0cf7074885e92b0e3f125978b41549\
            86d4fb202a3f331a3fb6cf349a3a70e49990f98fe4289761c8602c4e6ab1138d31d3b62218078b2f\
            3ba9a88e1d08d0dd4cea11",
        derive_key: "\
            b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c5827b91bf889b6b9\
            7c5477f535361caefca0b5d8c4746441c57617111933158950670f9aa8a05d791daae10ac683cbef\
            8faf897c84e6114a59d2173c3f417023a35d6983f2c7dfa57e7fc559ad751dbfb9ffab39c2ef8c4a\
            afebc9ae973a64f0c76551",
    },
    Vector {
        input_len: 1023,
        hash: "\
            10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b0559\
            2b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68\
            d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09\
            b6522d9c8d822f2f28f485",
        keyed_hash: "\
            c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e890316d2e6d8b8c2\
            5b0a5b2180f94fb1a158ef508c3cde45e2966bd796a696d3e13efd86259d756387d9becf5c8bf1ce\
            2192b87025152907b6d8cc33d17826d8b7b9bc97e38c3c85108ef09f013e01c229c20a83d9e8efac\
            5b37470da28575fd755a10",
        derive_key: "\
            74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea59c413264404661e9\
            e4d955409dfe4ad3aa487871bcd454ed12abfe2c2b1eb7757588cf6cb18d2eccad49e018c0d0fec3\
            23bec82bf1644c6325717d13ea712e6840d3e6e730d35553f59eff5377a9c350bcc1556694b924b8\
            58f329c44ee64b884ef00d",
    },
    Vector {
        input_len: 1024,
        hash: "\
            42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8\
            505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c20\
            75ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5c\
            a170ba441427ed9afa684e",
        keyed_hash: "\
            75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4\
            f49c864acb7adafe2478e824afe51c8919d06168414c265f298a8094b1ad813a9b8614acabac321f\
            24ce61c5a5346eb519520d38ecc43e89b5000236df0597243e4d2493fd626730e2ba17ac4d8824d0\
            9d1a4a8f57b8227778e2de",
        derive_key: "\
            7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a6896843027066c23b601d3ddfb39\
            1e90d5c8eccdef4ae2a264bce9e612ba15e2bc9d654af1481b2e75dbabe615974f1070bba84d5685\
            3265a34330b4766f8e75edd1f4a1650476c10802f22b64bd3919d246ba20a17558bc51c199efdec6\
            7e80a227251808d8ce5bad",
    },
    Vector {
        input_len: 1025,
        hash: "\
            d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155\
            358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b\
            3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595\
            adb992ae68ff12800ab67a",
        keyed_hash: "\
            357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d26\
            34a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d540\
            85d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf8263\
            6cff4542540a7738d5b930",
        derive_key: "\
            effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9\
            066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f4\
            62118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8\
            217cca46defa2751e7f3ad",
    },
    Vector {
        input_len: 2048,
        hash: "\
            e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec\
            9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf\
            618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f5\
            3a8863ac75655461cea8f9",
        keyed_hash: "\
            879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd10173b961cd574288\
            194b23ece278c330fbb8585485e74967f31352a8183aa782b2b22f26cdcadb61eed1a5bc144b8198\
            fbb0c13abbf8e3192c145d0a5c21633b0ef86054f42809df823389ee40811a5910dcbd1018af31c3\
            b43aa55201ed4edaac74fe",
        derive_key: "\
            7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23e2c11a1ebffcea4d\
            80447867b61badb1383d842d4e79645d48dd82ccba290769caa7af8eaa1bd78a2a5e6e94fbdab78d\
            9c7b74e894879f6a515257ccf6f95056f4e25390f24f6b35ffbb74b766202569b1d797f2d4bd9d17\
            524c720107f985f4ddc583",
    },
    Vector {
        input_len: 2049,
        hash: "\
            5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d741034\
            03822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5\
            448d519713e09413719431c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff6334\
            0285adec2aed3b51073ad3",
        keyed_hash: "\
            9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e0\
            0b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d43b81447be22d5d8186f8f5919ba6bcc6\
            846bd7d50726c06d245672c2ad4f61702c646499ee1173daa061ffe15bf45a631e2946d616a4c345\
            822f1151284712f76b2b0e",
        derive_key: "\
            2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf27316d8e9e79081a80b\
            046b60f6a263616f33ca464bd78d79fa18200d06c7fc9bffd808cc4755277a7d5e09da0f29ed150f\
            6537ea9bed946227ff184cc66a72a5f8c1e4bd8b04e81cf40fe6dc4427ad5678311a61f4ffc39d19\
            5589bdbc670f63ae70f4b6",
    },
    Vector {
        input_len: 3072,
        hash: "\
            b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608\
            335c09dc94ccf682f9951cdfc501bfe47b9c9189a6fc7b404d120258506341a6d802857322fbd20d\
            3e5dae05b95c88793fa83db1cb08e7d8008d1599b6209d78336e24839724c191b2a52a80448306e0\
            daa84a3fdb566661a37e11",
        keyed_hash: "\
            044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df19177022f302d0529e4174\
            cc507c463671217975e81dab02b8fdeb0d7ccc7568dd22574c783a76be215441b32e91b9a904be8e\
            a81f7a0afd14bad8ee7c8efc305ace5d3dd61b996febe8da4f56ca0919359a7533216e2999fc87ff\
            7d8f176fbecb3d6f34278b",
        derive_key: "\
            050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b3604131bbd6e3ba5\
            73b6dd682fa0a63e5b165d39fc43a625d00207607a2bfeb65ff1d29292152e26b298868e3b87be95\
            d6458f6f2ce6118437b632415abe6ad522874bcd79e4030a5e7bad2efa90a7a7c67e93f0a18fb283\
            69d0a9329ab5c24134ccb0",
    },
    Vector {
        input_len: 3073,
        hash: "\
            7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89\
            da9bf25bc27139ae65a324918a5f9b7828181e52cf373c84f35b639b7fccbb985b6f2fa56aea0c18\
            f531203497b8bbd3a07ceb5926f1cab74d14bd66486d9a91eba99059a98bd1cd25876b2af5a76c3e\
            9eed554ed72ea952b603bf",
        keyed_hash: "\
            68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a96d6da3fe985054d\
            3478865be9a092250839a697bbda74e279e8a9e69f0025e4cfddd6cfb434b1cd9543aaf97c635d1b\
            451a4386041e4bb100f5e45407cbbc24fa53ea2de3536ccb329e4eb9466ec37093a42cf62b82903c\
            696a93a50b702c80f3c3c5",
        derive_key: "\
            72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081576288e552647a9d\
            86481c2cae75c2dd4e7c5195fb9ada1ef50e9c5098c249d743929191441301c69e1f48505a4305ec\
            1778450ee48b8e69dc23a25960fe33070ea549119599760a8a2d28aeca06b8c5e9ba58bc19e11fe5\
            7b6ee98aa44b2a8e6b14a5",
    },
    Vector {
        input_len: 4096,
        hash: "\
            015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99\
            768eafe1623da896faf7e1114bebeadc1be30829b6f8af707d85c298f4f0ff4d9438aef948335612\
            ae921e76d411c3a9111df62d27eaf871959ae0062b5492a0feb98ef3ed4af277f5395172dbe5c311\
            918ea0074ce0036454f620",
        keyed_hash: "\
            befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0bbb64a36edb564e0\
            1e4b4aaf3b060092a6b838bea44afebd2deb8298fa562b7b597c757b9df4c911c3ca462e2ac89e9a\
            787357aaf74c3b56d5c07bc93ce899568a3eb17d9250c20f6c5f6c1e792ec9a2dcb715398d5a6ec6\
            d5c54f586a00403a1af1de",
        derive_key: "\
            1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9d78038f7b198596c\
            6cc4a9ccf93223c08722d684f240ff6569075ed81591fd93f9fff1110b3a75bc67e426012e558895\
            9cc5a4c192173a03c00731cf84544f65a2fb9378989f72e9694a6a394a8a30997c2e67f95a504e63\
            1cd2c5f55246024761b245",
    },
    Vector {
        input_len: 4097,
        hash: "\
            9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a112\
            51652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c426bd26f619eab5d70af9a418b845c608\
            840390f361630bd497b1ab44019316357c61dbe091ce72fc16dc340ac3d6e009e050b3adac4b5b2c\
            92e722cffdc46501531956",
        keyed_hash: "\
            00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc606db4976cfdd266\
            ae0abf667d9481831ff12e0caa268e7d3e57260c0824115a54ce595ccc897786d9dcbf495599cfd9\
            0157186a46ec800a6763f1c59e36197e9939e900809f7077c102f888caaf864b253bc41eea812656\
            d46742e4ea42769f89b83f",
        derive_key: "\
            aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8a897f66a400fed91\
            98fd61dd2d58d382458e64e100128075fc54b860934e8de2e84170734b06e1d212a117100820dbc4\
            8292d148afa50567b8b84b1ec336ae10d40c8c975a624996e12de31abbe135d9d159375739c33379\
            8a80c64ae895e51e22f3ad",
    },
    Vector {
        input_len: 5120,
        hash: "\
            9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a20\
            10ce8038c853e121e1544985133fccdd0a2d507e8e615e611e9a0ba4f47915f49e53d721816a9198\
            e8b30f12d20ec3689989175f1bf7a300eee0d9321fad8da232ece6efb8e9fd81b42ad161f6b9550a\
            069e66b11b40487a5f5059",
        keyed_hash: "\
            2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e209b4dc9209cd80ce7\
            c1f7c9a744658e7e288465717ae6e56d5463d4f80cdb2ef56495f6a4f5487f69749af0c34c2cdfa8\
            57f3056bf8d807336a14d7b89bf62bef2fb54f9af6a546f818dc1e98b9e07f8a5834da50fa28fb58\
            74af91bf06020d1bf0120e",
        derive_key: "\
            7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f6055d0cefd84d9d57f\
            e792d65a278fd20384ac6c30fdb340092f1a74a92ace99c482b28f0fc0ef3b923e56ade20c6dba47\
            e49227166251337d80a037e987ad3a7f728b5ab6dfafd6e2ab1bd583a95d9c895ba9c2422c24ea0f\
            62961f0dca45cad47bfa0d",
    },
    Vector {
        input_len: 31744,
        hash: "\
            62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7\
            b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713\
            087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a\
            5cc327a8ec470f4013226f",
        keyed_hash: "\
            efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a\
            7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08b628be420b5e830fade7c080e351a076\
            fbc38641ad80c736c8a18fe3c66ce12f95c61c2462a9770d60d0f77115bbcd3782b593016a4e728d\
            4c06cee4505cb0c08a42ec",
        derive_key: "\
            39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e9759adeb797a3fbf\
            771b1bcea30150a020e317982bf0d6e7d14dd9f064bc11025c25f31e81bd78a921db0174f03dd481\
            d30e93fd8e90f8b2fee209f849f2d2a52f31719a490fb0ba7aea1e09814ee912eba111a9fde9d5c2\
            74185f7bae8ba85d300a2b",
    },
    Vector {
        input_len: 102400,
        hash: "\
            bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c\
            3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f355\
            85a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58\
            eb7d01dd42248204f45f8e",
        keyed_hash: "\
            1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7f9dbdd3e1d81dcbc\
            a3ba241bb18760f207710b751846faaeb9dff8262710999a59b2aa1aca298a032d94eacfadf1aa19\
            2418eb54808db23b56e34213266aa08499a16b354f018fc4967d05f8b9d2ad87a7278337be9693fc\
            638a3bfdbe314574ee6fc4",
        derive_key: "\
            4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6d83a3e041bc3a48d\
            f2879f4a0a3ed40e7c961c73eff740f3117a0504c2dff4786d44fb17f1549eb0ba585e40ec29bf77\
            32f0b7e286ff8acddc4cb1e23b87ff5d824a986458dcc6a04ac83969b80637562953df51ed1a7e90\
            a7926924d2763778be8560",
    },
];

/// Checks one mode against its expected 131-byte output, through both `finalize` and
/// `finalize_xof`, and with the input fed in pieces of several sizes.
fn check(new_hasher: impl Fn() -> Hasher, input: &[u8], expected_hex: &str, what: &str) {
    let expected = hex(expected_hex);
    for piece in [input.len().max(1), 1, 63, 64, 65, 1023, 1024, 1025, 4096] {
        let mut hasher = new_hasher();
        input.chunks(piece).for_each(|chunk| {
            hasher.update(chunk);
        });
        let mut xof = [0u8; 131];
        hasher.finalize_xof(&mut xof);
        assert_eq!(xof[..], expected[..], "{what} length {} piece {piece}", input.len());
        assert_eq!(hasher.finalize()[..], expected[..OUT_LEN], "{what} finalize");
    }
}

#[test]
fn official_test_vectors() {
    for vector in VECTORS {
        let input = pattern(vector.input_len);
        check(Hasher::new, &input, vector.hash, "hash");
        check(|| Hasher::new_keyed(KEY), &input, vector.keyed_hash, "keyed_hash");
        check(|| Hasher::new_derive_key(CONTEXT), &input, vector.derive_key, "derive_key");
        assert_eq!(hash(&input)[..], hex(vector.hash)[..OUT_LEN]);
        assert_eq!(keyed_hash(KEY, &input)[..], hex(vector.keyed_hash)[..OUT_LEN]);
        assert_eq!(derive_key(CONTEXT, &input)[..], hex(vector.derive_key)[..OUT_LEN]);
    }
}

#[test]
fn shorter_outputs_are_prefixes() {
    let hasher = Hasher::new_keyed(KEY).update(b"sibuna").clone();
    let mut long = [0u8; 200];
    hasher.finalize_xof(&mut long);
    for len in [0, 1, 8, 16, 31, 32, 33, 64, 65, 199] {
        let mut short = std::vec![0u8; len];
        hasher.finalize_xof(&mut short);
        assert_eq!(short[..], long[..len], "length {len}");
    }
}

#[test]
fn finalize_leaves_the_hasher_usable() {
    let mut hasher = Hasher::default();
    hasher.update(b"ab");
    let partial = hasher.finalize();
    assert_eq!(partial, hash(b"ab"));
    hasher.update(b"c");
    assert_eq!(hasher.finalize(), hash(b"abc"));
    let forked = hasher.clone().update(b"d").finalize();
    assert_eq!(forked, hash(b"abcd"));
    assert_eq!(hasher.finalize(), hash(b"abc"));
}
