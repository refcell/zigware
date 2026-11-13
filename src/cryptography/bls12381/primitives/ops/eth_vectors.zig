//! Ethereum BLS12-381 test vectors (ethereum/bls12-381-tests v0.1.2), as embedded in
//! commonware's `ops` tests: MinPk signing and verification with the G2 message tag.

pub const SignVector = struct {
    name: []const u8,
    private: []const u8,
    message: []const u8,
    signature: []const u8,
};
pub const VerifyVector = struct {
    name: []const u8,
    public: []const u8,
    message: []const u8,
    signature: []const u8,
    valid: bool,
};

pub const sign = [_]SignVector{
    .{
        .name = "sign_case_8cd3d4d0d9a5b265",
        .private = "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98a" ++
            "bbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03b" ++
            "e39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
    },
    .{
        .name = "sign_case_11b8c7cad5238946",
        .private = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63" ++
            "926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279" ++
            "527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
    },
    .{
        .name = "sign_case_84d45c9c7cca6b92",
        .private = "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8" ++
            "638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0" ++
            "559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
    },
    .{
        .name = "sign_case_142f678a8d05fcd1",
        .private = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff97" ++
            "4ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc" ++
            "085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
    },
    .{
        .name = "sign_case_37286e1a6d1f6eb3",
        .private = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665a" ++
            "a635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea" ++
            "1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
    },
    .{
        .name = "sign_case_7055381f640f2c1d",
        .private = "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219f" ++
            "abb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f" ++
            "07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
    },
    .{
        .name = "sign_case_c82df61aa3ee60fb",
        .private = "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6" ++
            "076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24" ++
            "802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
    },
    .{
        .name = "sign_case_d0e28d7e76eb6e9c",
        .private = "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98a" ++
            "bbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03b" ++
            "e39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
    },
    .{
        .name = "sign_case_f2ae1097e7d0e18b",
        .private = "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2" ++
            "677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346" ++
            "da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
    },
};

pub const verify = [_]VerifyVector{
    .{
        .name = "verify_infinity_pubkey_and_infinity_signature",
        .public = "c000000000000000000000000000000000000000000000000000000000000000" ++
            "00000000000000000000000000000000",
        .message = "1212121212121212121212121212121212121212121212121212121212121212",
        .signature = "c000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_2ea479adf8c40300",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98a" ++
            "bbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03b" ++
            "e39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_2f09d443ab8a3ac2",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63" ++
            "926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279" ++
            "527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_6b3b17f6962a490c",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65" ++
            "aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756" ++
            "acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_6eeb7c52dfd9baf0",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665a" ++
            "a635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea" ++
            "1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_8761a0b7e920c323",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2" ++
            "677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346" ++
            "da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b71ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_195246ee3bd3b6ec",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8" ++
            "638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0" ++
            "559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_3208262581c8fc09",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff97" ++
            "4ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc" ++
            "085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363ffffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_d34885d766d5f705",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219f" ++
            "abb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f" ++
            "07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075effffffff",
        .valid = false,
    },
    .{
        .name = "verify_tampered_signature_case_e8a50c445c855360",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6" ++
            "076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24" ++
            "802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        .valid = false,
    },
    .{
        .name = "verify_valid_case_2ea479adf8c40300",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98a" ++
            "bbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03b" ++
            "e39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_2f09d443ab8a3ac2",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63" ++
            "926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279" ++
            "527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_6b3b17f6962a490c",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65" ++
            "aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756" ++
            "acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_6eeb7c52dfd9baf0",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665a" ++
            "a635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea" ++
            "1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_8761a0b7e920c323",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2" ++
            "677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346" ++
            "da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_195246ee3bd3b6ec",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8" ++
            "638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0" ++
            "559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_3208262581c8fc09",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff97" ++
            "4ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc" ++
            "085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_d34885d766d5f705",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219f" ++
            "abb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f" ++
            "07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        .valid = true,
    },
    .{
        .name = "verify_valid_case_e8a50c445c855360",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6" ++
            "076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24" ++
            "802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        .valid = true,
    },
    .{
        .name = "verify_wrong_pubkey_case_2ea479adf8c40300",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65" ++
            "aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756" ++
            "acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_2f09d443ab8a3ac2",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6" ++
            "076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24" ++
            "802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_6b3b17f6962a490c",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff97" ++
            "4ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc" ++
            "085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_6eeb7c52dfd9baf0",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2" ++
            "677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346" ++
            "da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_8761a0b7e920c323",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8" ++
            "638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0" ++
            "559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_195246ee3bd3b6ec",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "abababababababababababababababababababababababababababababababab",
        .signature = "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665a" ++
            "a635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea" ++
            "1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_3208262581c8fc09",
        .public = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491" ++
            "af75d0707adab3b70c6a6a580217bf81",
        .message = "5656565656565656565656565656565656565656565656565656565656565656",
        .signature = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98a" ++
            "bbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03b" ++
            "e39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_d34885d766d5f705",
        .public = "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9" ++
            "f829fdd7963afdf972e5e77854051f6f",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63" ++
            "926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279" ++
            "527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        .valid = false,
    },
    .{
        .name = "verify_wrong_pubkey_case_e8a50c445c855360",
        .public = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20f" ++
            "d6e10c1b77654d067c0618f6e5a7f79a",
        .message = "0000000000000000000000000000000000000000000000000000000000000000",
        .signature = "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219f" ++
            "abb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f" ++
            "07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        .valid = false,
    },
    .{
        .name = "verifycase_one_privkey_47117849458281be",
        .public = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58" ++
            "6c55e83ff97a1aeffb3af00adb22c6bb",
        .message = "1212121212121212121212121212121212121212121212121212121212121212",
        .signature = "a42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b470082923205" ++
            "2b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770" ++
            "605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763",
        .valid = true,
    },
};
