package main

// Known-answer vectors compiled into the binary for `hashsmith selftest`.
// See selftest.go for what each source class means.

// Hashcat mode 6211 self-test header: TrueCrypt RIPEMD-160 + AES-XTS,
// passphrase "hashcat". Kept separate because the canonical record is a raw
// 512-byte header rather than a tagged, field-oriented string.
const tcRIPEMD160AESHeader = "87914967f14737a67fb460f27b8aeb81de2b41bf2740b3dd78784e02763951daa47c7ca235e75c22ec8d959d6b67f7eedefad61e6a0d038079d3721a8e7215e415671e8c7b3dbed6453a114e6db89a52be9a9c1698a9c698f1e37f80d7afaf0efba82b6e5f5df32bd289b95343c6775e2c7f025ef1d8bfae84042a92546e15b635b5fade3aef6ee52a7a5ab018d33ea98bc115dfc62af606187fbab8cbda6e8417402c722ca8c2b07e6ca6a33bf94b2ce2a819a9f8cfaa5af70e3af6e5350d3a306f036f13ff5ba97d5728d5f6413b482c74f528211ae77b6c169215c5487d5a3ce23736b16996b86c71b12d120df28ef322f5143d9a258d0ae7aaa8c193a6dcb5bf18e3c57b5474d24b843f8dd4e83a74109396ddb4f0c50d3657a7eacc8828568e51202de48cd2dfe5acbe3d8840ade1ce44b716d5c0008f2b21b9981353cb12b8af2592a5ab744ae83623349f551acf371c81f86d17a8422654989f078179b2386e2aa8375853a1802cd8bc5d41ce45795f78b80e69fcfa3d14cf9127c3a33fa2dc76ad73960fb7bce15dd489e0b6eca7beed3733887cd5e6f3939a015d4d449185060b2f3bbad46e46d417b8f0830e91edd5ebc17cd5a99316792a36afd83fa1edc55da25518c8e7ff61e201976fa2c5fc9969e05cbee0dce7a0ef876b7340bbe8937c9d9c8248f0e0eae705fe7e1d2da48902f4f3e27d2cf532b7021e18"

const snmpV3Packet = "30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a"
const snmpV3EngineID = "80001f88808106d566db57fd6000000000"
const snmpV3Digest = "1b37c3ea872731f922959e90"
const snmpV3Mode0Vector = "$SNMPv3$0$45889431$" + snmpV3Packet + "$" + snmpV3EngineID + "$" + snmpV3Digest
const snmpV3Mode1Vector = "$SNMPv3$1$45889431$" + snmpV3Packet + "$" + snmpV3EngineID + "$" + snmpV3Digest
const snmpV3SHA1Vector = "$SNMPv3$0$1$000000000000000000000000$" + snmpV3EngineID + "$71fcb2b5a7845084c9cb8a13"
const snmpV3Mode2Vector = "$SNMPv3$2$45889431$30818f02010330110204371780f3020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f534841040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204073557d50201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$81f14f1930589f26f6755f6b"
const snmpV3Mode3Vector = "$SNMPv3$3$45889431$308197020103301102047aa1a79e020300ffe30401010201030440303e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d3232340410000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204272f76620201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$2f7a3891dd2e27d3f567e4d6d0257962"
const snmpV3Mode4Vector = "$SNMPv3$4$45889431$30819f020103301102047fc51818020300ffe304010102010304483046041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d32353604180000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602040efec2600201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$36d655bfeb59e933845db47d719b68ac7bc59ec087eb89a0"
const snmpV3Mode5Vector = "$SNMPv3$5$45889431$3081a70201033011020455c0c85c020300ffe30401010201030450304e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d333834042000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411b3c3590201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$89424907553231aaa27055f4b3b0a97c626ed4cdc4b660d903765b607af792a5"
const snmpV3Mode6Vector = "$SNMPv3$6$45889431$3081b702010330110204367c80d4020300ffe30401010201030460305e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d35313204300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602046ea3546f0201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$9e4681768d5dee9e2d0ca7380dfa19f0a0f805c550142b889af548f5506c2c3587df980707600b58d97ed1beaa9feaf9"

const radmin3PublishedVector = "$radmin3$75007300650072006e0061006d006500*c63bf695069d564844c4849e7df6d41f1fbc5f3a7d8fe27c5f20545a238398fa*0062fb848c21d606baa0a91d7177daceb69ad2f6d090c2f1b3a654cfb417be66f739ae952f5c7c5170743459daf854a22684787b24f8725337b3c3bd1e0f2a6285768ceccca77f26c579d42a66372df7782b2eefccb028a0efb51a4257dd0804d05e0a83f611f2a0f10ffe920568cc7af1ec426f450ec99ade1f2a4905fd319f8c190c2db0b0e24627d635bc2b4a2c4c9ae956b1e02784c9ce958eb9883c60ba8ea2731dd0e515f492c44f39324e4027587c1330f14216e17f212eaec949273797ae74497782ee8b6f640dd2d124c59db8c37724c8a5a63bad005f8e491b459ff1b92f861ab6d99a2548cb8902b0840c7f20a108ede6bf9a60093053781216fe"
const hccapxHashcatSelfTest = "4843505804000000000235380000000000000000000000000000000000000000000000000000000000000151aecc428f182acefbd1a9e62d369a079265784da83ba4cf88375c44c830e6e5aa5d6faf352aa496a9ee129fb8292f7435df5420b823a1cd402aed449cced04f552c5b5acfebf06ae96a09c96d9a01c443a17aa62258c4f651a68aa67b0001030077fe010900200000000000000001a4cf88375c44c830e6e5aa5d6faf352aa496a9ee129fb8292f7435df5420b8230000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018dd160050f20101000050f20201000050f20201000050f20200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

var selfTestVectors = []selfTestVector{
	// ── Raw digests: the standard "abc" vectors from each specification ──────
	{"md5", "abc", "", "900150983cd24fb0d6963f7d28e17f72", srcPublished},
	{"sha1", "abc", "", "a9993e364706816aba3e25717850c26c9cd0d89d", srcPublished},
	{"sha224", "abc", "", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", srcPublished},
	{"sha256", "abc", "", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", srcPublished},
	{"sha384", "abc", "", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", srcPublished},
	{"sha512", "abc", "", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", srcPublished},
	{"sha512_224", "abc", "", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", srcPublished},
	{"sha512_256", "abc", "", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", srcPublished},
	{"sha3_224", "abc", "", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", srcPublished},
	{"sha3_256", "abc", "", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", srcPublished},
	{"sha3_384", "abc", "", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", srcPublished},
	{"sha3_512", "abc", "", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", srcPublished},
	{"ripemd128", "abc", "", "c14a12199c66e4ba84636b0f69144c77", srcPublished},
	{"ripemd160", "abc", "", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", srcPublished},
	{"ripemd256", "abc", "", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", srcPublished},
	{"ripemd320", "abc", "", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d", srcPublished},
	{"sm3", "abc", "", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", srcPublished},
	{"blake2b", "abc", "", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923", srcPublished},
	{"blake2b256", "abc", "", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", srcCrosschecked},
	{"blake2b384", "abc", "", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4", srcCrosschecked},
	{"blake2s", "abc", "", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", srcPublished},
	{"shake128-256", "abc", "", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8", srcCrosschecked},
	{"shake256-512", "abc", "", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4", srcCrosschecked},

	// ── HMAC (message supplied as the salt) ──────────────────────────────────
	{"hmac-md5", "abc", "salt", "32b4db8a8185e0bdfe5b3b343d3a894a", srcCrosschecked},
	{"hmac-sha1", "abc", "salt", "99895f95046de53f03060cea36c24f7075cc0e54", srcCrosschecked},
	{"hmac-sha256", "abc", "salt", "fbf087a3135b4af8615b2836534788c59b55acdb598f4d015b03cf4e72f07d8e", srcCrosschecked},
	{"hmac-sha512", "abc", "salt", "ef1d6c5a22a8768e729685351d67e81a850a846ab9642278e6298f40a75f3c6ed2721a8741e6ef4a11f2c0989c39d06d61e63da0d8bb062d3c0a03ceca9c7d3d", srcCrosschecked},
	{"hmac-md5-saltkey", "abc", "salt", "d711a5cc511fb1a7d5f19d7c911aff2d", srcCrosschecked},
	{"hmac-sha256-saltkey", "abc", "salt", "5031dfb5b067c1d64e70ad09acb9c5421c194ebb0ecff635f6eea656d1fc8e2c", srcCrosschecked},

	// ── Unix login / crypt(3) ────────────────────────────────────────────────
	{"md5crypt", "password", "", "$1$abcdefgh$G//4keteveJp0qb8z2DxG/", srcPublished},
	{"apr1", "hashsmith", "", "$apr1$abcdefgh$U1gIt51iVe84gztna6VnP0", srcCrosschecked},
	{"sha256crypt", "password", "", "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/", srcPublished},
	{"sha512crypt", "password", "", "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1", srcPublished},
	{"descrypt", "password", "", "abJnggxhB/yWI", srcPublished},

	// ── Windows ─────────────────────────────────────────────────────────────
	{"ntlm", "hashcat", "", "b4b9b02e6f09a9bd760f388b67351e2b", srcPublished},

	// ── Application and framework formats ───────────────────────────────────
	{"phpass", "hashcat", "", "$P$984478476IagS59wHZvyQMArzfx58u.", srcPublished},
	{"drupal7", "hashcat", "", "$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf", srcPublished},
	{"mediawiki", "hashsmith", "", "$B$a1b2c3d4$c98b583edcb1cdccf2a4b855442a6cc6", srcCrosschecked},
	{"vbulletin", "hashsmith", "", "209a1ebf02b22c103e1b3896b895ecd2:Zx9", srcCrosschecked},
	{"redmine", "hashsmith", "", "e68c45f4f20e4e1958daa2c1a7ff80ea39f1dd97:3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d", srcCrosschecked},
	{"peoplesoft", "hashsmith", "", "2uCd2T/LX41DjVEwFi9KoRahpX4=", srcCrosschecked},
	{"episerver", "hashsmith", "", "$episerver$*0*MjEwNDE5NzcyNg==*aKdKfczl/7l2BtCK8vtVQ0sZoMQ=", srcCrosschecked},
	{"episerver", "hashsmith", "", "$episerver$*1*MjEwNDE5NzcyNg==*2AS3xW1AuqiQczMED1VAxsUwuUzlgR0pRikE3r09tKI=", srcCrosschecked},
	{"azuresync", "hashsmith", "", "v1;PPH1_MD4,10920c8b4d1f2a3b,100,112751a58105737a61461ec5c0ea567c068b154e5e89e723b1f2b80997557f16", srcCrosschecked},
	{"hmailserver", "hashsmith", "", "aB3xY9f7e20052c00664fe2b773123e52b8cdd393bcb09518b63ea390fe30eefa11688", srcCrosschecked},

	// ── Containers ──────────────────────────────────────────────────────────
	{"pfx", "hashsmith", "", "$pfx$*sha256*2048*005070587dcdb26f1bf120f0e0889794*d0e94137693baa9ad0ea6c8fb1938969a220d8186f03e43c3021ea3e38884725*3082098e308203fa06092a864886f70d010706", srcCrosschecked},
	{"pfx", "hashsmith", "", "$pfx$*sha1*2048*005070587dcdb26f1bf120f0e0889794*930ba72f5f6cfe1982771f3ac4f31cc2c3038319*3082098e308203fa06092a864886f70d010706", srcCrosschecked},
	{"pwsafe", "hashsmith", "", "$pwsafe$*3*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*2048*6f2ad9b3cebdaa86a663f2a202b3d0b00e471ce104995ee07255e2d3edb31a37", srcCrosschecked},

	// ── Generic salted and composite constructions ──────────────────────────
	{"md5-pass-salt", "hashcat", "", "01dfae6e5d4d90d9892622325959afbe:7050461", srcPublished},
	{"md5-salt-pass", "hashcat", "", "f0fda58630310a6dd91a7d8f0a4ceda2:4225637426", srcPublished},
	{"sha1-pass-salt", "hashcat", "", "2fc5a684737ce1bf7b3b239df432416e0dd07357:2014", srcPublished},
	{"sha1-salt-pass", "hashcat", "", "cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024", srcPublished},
	{"sha256-pass-salt", "hashcat", "", "c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528", srcPublished},
	{"sha256-salt-pass", "hashcat", "", "eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617", srcPublished},
	{"md5-salt-md5pass", "hashsmith", "Zx9", "b20c905b199b3e72785c8c7708aeddfb", srcCrosschecked},
	{"md5-salt-pass-salt", "hashsmith", "Zx9", "903d7e353140c6e09b6bcf38a574594f", srcCrosschecked},
	{"md5-md5salt-md5pass", "hashsmith", "Zx9", "d9afd016defaf2c9cc7ec7d91b674b09", srcCrosschecked},
	{"sha1-salt-sha1pass", "hashsmith", "Zx9", "1498106ecd17f9f820d38a7578ba444d33351e54", srcCrosschecked},
	{"sha256-salt-pass-salt", "hashsmith", "Zx9", "e96b01deda9eee797d01383bb9e611f755cdc2f35cbe0778e5d0e69f3a47aafb", srcCrosschecked},
	{"sha256-salt-uppersha1pass", "hashsmith", "Zx9", "1a93033337810e3624427730236f76fcd3ecbb91123711401d58b54b8b2b38ec", srcCrosschecked},
	{"sha256-salt-utf16lepass", "hashsmith", "Zx9", "7debd89b3b350568a11e74d36e26b85b7cc395483a273f30e3b67f3e5cfc1ac4", srcCrosschecked},
	{"md5-sha1pass-md5pass-sha1pass", "hashsmith", "Zx9", "743aaa6545dc3fec867bd2d9eaed4823", srcCrosschecked},
	{"sha512-sha512binpass", "hashsmith", "", "67744bf0ad8a06ccc73359acf47a469430958dc95ea59dc92651466fd5708740077b21d59dad321aa61f7feafe2a92c75521745a4ee2fedcc7912b7e3ccf6c67", srcCrosschecked},

	// ── Nested digests ──────────────────────────────────────────────────────
	{"md5-md5", "hashcat", "", "a936af92b0ae20b1ff6c3347a72e5fbe", srcPublished},
	{"md5-md5-md5", "hashcat", "", "9882d0778518b095917eb589f6998441", srcPublished},
	{"sha1-sha1", "hashcat", "", "3db9184f5da4e463832b086211af8d2314919951", srcPublished},
	{"md5-sha1", "hashcat", "", "288496df99b33f8f75a7ce4837d1b480", srcPublished},
	{"sha1-md5", "hashcat", "", "92d85978d884eb1d99a51652b1139c8279fa8663", srcPublished},

	// ── Harvested from the repository's own verified test vectors ───────────
	// Passwords of "hashcat" come from Hashcat's published example hashes;
	// the rest were generated and cross-checked when those tests were written.
	{"1password", "hashcat", "", "1000:9e55bd14cb90f5e1:99a89704bc67d6921ab393ca46ee7973e0d5227938a6d669cdc920ad7ae857eb4163dcccf6770190f80d3478c62904827c59d5c97f2a0f16ea9f3aee6992d921b0244617e309a8283c91a21c524561923658dee0d4d304465bac5f766ef26b02534e44a7d1506088f95f9610dbfaf1ace6cf4368921a28367415e7d76938faf3d7a27750eaf74c1855a671ad7b2e4fdb30734022c37565ec8e30681db367ad8be49ce3927232ccd8e0d8a4e726acf88fa8dedf32c24ba771a3f5eb2aae13180ca4c29e2b7fccec4bc4e4d32eb01c6b12405a5a2b8d3aea44d7745be76bec9068ec2dd13d227b3bdb4962143dfc74496e00e228465b6f214428243b3fca652c3f8661915fcae0a5db919f87f9e9202ae7e0a4080849dc5003d7618585746ec637dd9d17cb97be9f2eb550fd539d51ae4a6d07c63903c83c780bb8520ba6462bae6f1dec54fee0707e82345b39c46befd3eefe0c33e30adb13cafe7dc4f18b53bee60dccf92c80cfae1671f9e3c6b0cf0ed278bfbdbd69ee910130554d8348287c9372e0f437194018355f71b5236114f03b7a58036b85ac8f089b7eaa72ab8997c9e26c40a095014b64d5c3b9221e59f5b9e7dd1d730420875b73a6ad841f68c2004e5622400905000c977edb625d54c6a42cecfc9009bb4489ebb4d1e339e0d014a972364e378441c761aad8c8929f753917b9a1e1a316831cb9d6ba92354a47202b78ab2f42f2c99284c12d3e212ebf8ea8ec683aeb62c0e5d588cca9cc08aac3ead97831bfa1f698dac9f857e8cdd9ec4b15cffb5900f2f951c657f831689ac6199033b13cecf4b29d84fb06f422acd3db566d7ec6b664325c4331ff35963553c26e94af6eb5b36fe79f14bf3a30f4964ded7991ef5d859ebbb0e98c821b21f9620fca9086f9b3b2a7ad8360c4a635c481f1ef4990f7f0ec4fde37723b4639ee633bdb32be6bf31298a4574381d95831d65b3e8e6352b1207a684401a0f3fcff65e0ed1e6ec714c07526896468daeb056cbe49d82b87092e53ac40cfba049983ce8923bed2de773d15a5e87a88041f72c34d8c0436f95368ec73abfdd1d21897f649e1de9e7198e9db342c93b3b8b0d3af6c4867d63fed394674e5b02c92b7698d5457d2cca773abaad69c4a0a36e468a40d14b8bd73fa1d9074c8881158e10e4243045ab254775bda1e7e89a68005d91bb67044ed407f221d1028d034aedcfea3b527725607bd5c3f880557cfc6c2c0bb3361ae131261b8a5ebf3b53521fdd731ec2413c61bc78a1ab7f78057abd1c5459250fba0e0d57c1f4ebd3e1871ce0f5bfd44d2790d946936eef03e14e81f33f5484eec0a76910c253bf2777232be1a3593678f27225b035999d9ffb675685457b48928db1f1be6c3f206ad2efc764f8ba77a38b439f1e28318a1b077fe0c9e36fa6ed0df0f052d9aadd56b1514b5d01a44161fcea20f6326fab1ee3d7f79", srcPublished},
	{"ansible", "hashsmith", "", "$ansible$0*0*00112233445566778899aabbccddeeff*f7c3cc30dd11c057fc913c1a39c062fbda11319016b329897480ea4be6fc03ab*aabbccddeeff00112233445566778899", srcCrosschecked},
	{"axcrypt-sha1", "hashcat", "", "$axcrypt_sha1$b89eaac7e61417341b710b727768294d0e6a277b", srcPublished},
	{"bitcoin", "hashcat", "", "$bitcoin$96$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54$16$1563277210780230$158555$96$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174$66$625882875480513751851333441623702852811440775888122046360561760525", srcPublished},
	{"bitlocker", "hashcat", "", "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb", srcPublished},
	{"bitwarden", "hashsmith", "", "$bitwarden$2*100000*dXNlckBleGFtcGxlLmNvbQ==*1T7YrDYENfccHpf9+YnmLc1iQlw0SOoKPU7xefd1bRM=", srcCrosschecked},
	{"blockchain", "hashcat", "", "$blockchain$v2$5000$288$06063152445005516247820607861028813ccf6dcc5793dc0c7a82dcd604c5c3e8d91bea9531e628c2027c56328380c87356f86ae88968f179c366da9f0f11b09492cea4f4d591493a06b2ba9647faee437c2f2c0caaec9ec795026af51bfa68fc713eaac522431da8045cc6199695556fc2918ceaaabbe096f48876f81ddbbc20bec9209c6c7bc06f24097a0e9a656047ea0f90a2a2f28adfb349a9cd13852a452741e2a607dae0733851a19a670513bcf8f2070f30b115f8bcb56be2625e15139f2a357cf49d72b1c81c18b24c7485ad8af1e1a8db0dc04d906935d7475e1d3757aba32428fdc135fee63f40b16a5ea701766026066fb9fb17166a53aa2b1b5c10b65bfe685dce6962442ece2b526890bcecdeadffbac95c3e3ad32ba57c9e", srcPublished},
	{"chap", "hashsmith", "", "81474a4f7a3dbf22e071a02c10e54b47:abcdef0123456789:1b", srcCrosschecked},
	{"cisco8", "hashcat", "", "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk", srcPublished},
	{"cisco9", "hashcat", "", "$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6", srcPublished},
	{"citrix", "hashcat", "", "1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea", srcPublished},
	{"cram-md5", "hashsmith", "", "$cram_md5$PDEyMzQuNTY3OEBzZXJ2ZXI+$c21pdGggNGVkNDY0NGI2ZmY0OWViYmU1OGE5MjY2MWQzMmE4MTg=", srcCrosschecked},
	{"dcc", "hashcat", "", "4dd8965d1d476fa0d026722989a6b772:3060147285011", srcPublished},
	{"dcc2", "hashcat", "", "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f", srcPublished},
	{"electrum", "hashcat", "", "$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea", srcPublished},
	{"half-md5", "hashsmith", "", "ed1a4cb602d45090", srcCrosschecked},
	{"ipmi", "hashcat", "", "b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef", srcPublished},
	{"itunes", "hashcat", "", "$itunes_backup$*9*b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642*10000*4542263740587424862267232255853830404566**", srcPublished},
	{"jwt", "hashsmith", "", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbWl0aCIsImFkbWluIjp0cnVlfQ.FnpR61iqT7rqJqNFIrEz9AkzR8LySOtfK-koWIhz1ZY", srcCrosschecked},
	{"keepass", "hashsmith", "", "$keepass$*4*d*14*67108864*2*19*7264517c7aa1a76af9eaaf503768d2a51e5844430388731829035994b06a7618*a449a3fb4f23e8ffe80051c585e348a78be1dee3801bd6b93dd919d43ae8bc66*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000a449a3fb4f23e8ffe80051c585e348a78be1dee3801bd6b93dd919d43ae8bc6607100000005b6a190d99560c00cb0e09ae31bf9d3b0b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c050100000049080000000e0000000000000005010000004d0800000000000004000000000401000000500400000002000000420100000053200000007264517c7aa1a76af9eaaf503768d2a51e5844430388731829035994b06a761804010000005604000000130000000000040000000d0a0d0a*85bb3e19b1c5ac2e1ffb9ebdbdf1b549e42e5de2776668ea29a26ff428d60422", srcCrosschecked},
	{"krb5asrep", "hashcat", "", "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac", srcPublished},
	{"ldap", "hashsmith", "", "{CRYPT}$1$abcdefgh$t4yIjTehTKVzyLza7AROx.", srcCrosschecked},
	{"mongodb", "hashsmith", "", "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM=", srcCrosschecked},
	{"oracle11g", "hashsmith", "", "f49ad07d1f71398cf0e475ffa0d1b56575e407fd0011223344556677889a", srcCrosschecked},
	{"oracle12c", "hashcat", "", "78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225", srcPublished},
	{"pdf-r6", "hashcat", "", "$pdf$5*5*256*-1028*1*16*20583814402184226866485332754315*127*f95d927a94829db8e2fbfbc9726ebe0a391b22a084ccc2882eb107a74f7884812058381440218422686648533275431500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000", srcPublished},
	{"sap-b", "hashcat", "", "USER$C8B48F26B87B7EA7", srcPublished},
	{"sap-fg", "hashcat", "", "USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0", srcPublished},
	{"scram", "hashsmith", "", "SCRAM-SHA-256$4096:ABEiM0RVZnc=$tXvV/5d2dbq937pl1Urt3L2m8LXy7/llbOPTaIXXgsI=:s5u1rzVInmgZSrQkhL722KLzdU3PzDktG2BMsuT009c=", srcCrosschecked},
	{"sip", "hashcat", "", "$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d", srcPublished},
	{"solarwinds", "hashsmith", "", "$solarwinds$0$admin$gWiHE/NPgE/YtGzyLmH3kpG51robFZFQ4re8mH6veZYq4AaYoebzopWtF3aEvsig5dQc7Q6IUMfZEdPF+Hu9Ng==", srcCrosschecked},
	{"sybase", "hashcat", "", "0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2", srcPublished},
	{"wpa", "password", "", "WPA*01*6d3c40446a165cfeb121c82f18bf97d8*001122334455*8899aabbccdd*49454545", srcCrosschecked},

	// ── Hashcat published example hashes (password "hashcat") ──────────────
	{"md5-utf16le-pass-salt", "hashcat", "", "b31d032cfdcf47a399990a71e43c5d2a:144816", srcPublished},
	{"md5-salt-utf16le-pass", "hashcat", "", "d63d0e21fdc05f618d55ef306c54af82:13288442151473", srcPublished},
	{"md5-utf16le", "hashcat", "", "2303b15bfa48c74a74758135a0df1201", srcPublished},
	{"sha1-utf16le-pass-salt", "hashcat", "", "c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225", srcPublished},
	{"sha1-salt-utf16le-pass", "hashcat", "", "5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872", srcPublished},
	{"sha1-utf16le", "hashcat", "", "b9798556b741befdbddcbf640d1dd59d19b1e193", srcPublished},
	{"sha224-pass-salt", "hashcat", "", "0cf361904f4b0234cf4ade8496d8c11c04e5982db967603e82f22b2f:89452466460220844541730694146873525188525677", srcPublished},
	{"sha224-salt-pass", "hashcat", "", "4258a61d3d0d5a5b6796f0ab02d081e998fe657d55d22091d3b51409:36669207", srcPublished},
	{"sha256-utf16le-pass-salt", "hashcat", "", "4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128", srcPublished},
	{"sha256-salt-utf16le-pass", "hashcat", "", "a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678", srcPublished},
	{"sha256-utf16le", "hashcat", "", "9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82", srcPublished},
	{"sha512-pass-salt", "hashcat", "", "e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260", srcPublished},
	{"sha512-salt-pass", "hashcat", "", "976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127", srcPublished},
	{"sha512-utf16le-pass-salt", "hashcat", "", "13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589", srcPublished},
	{"sha512-salt-utf16le-pass", "hashcat", "", "bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423", srcPublished},
	{"sha512-utf16le", "hashcat", "", "79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697", srcPublished},
	{"md5-upper-md5", "hashcat", "", "b8c385461bb9f9d733d3af832cf60b27", srcPublished},
	{"mysql41", "hashcat", "", "fcf7c1b8749cf99d88e5f34271d636178fb5d130", srcPublished},
	{"lm", "hashcat", "", "299bd128c1101fd6", srcPublished},
	{"sha384-pass-salt", "hashcat", "", "ca1c843a7a336234baf9db2e10bc38824ce523402fbd7741286b1602bdf6cb869a45289bb9fb706bd404b9f3842ff729:2746460797049820734631508", srcPublished},
	{"sha384-salt-pass", "hashcat", "", "63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2:93362", srcPublished},
	{"sha384-utf16le-pass-salt", "hashcat", "", "3516a589d2ed4071bf5e36f22e11212b3ad9050b9094b23067103d51e99dcb25c4dc397dba8034fed11a8184acfbb699:577730514588712", srcPublished},
	{"sha384-salt-utf16le-pass", "hashcat", "", "316e93ea8e04de3e5a909c53d36923a31a16c1b9e89b44201d6082f87ca49c5bca53cad65f685207db3ea2ccc7ca40f8:700067651", srcPublished},
	{"sha384-utf16le", "hashcat", "", "48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8", srcPublished},
	{"scrypt", "hashcat", "", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=", srcPublished},
	{"pbkdf2", "hashcat", "", "sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt", srcPublished},

	// ── Legacy and non-cryptographic digests ────────────────────────────────
	// The published "abc" values below were each confirmed against Hashsmith's
	// own independently-written implementation before being pinned here.
	{"md2", "abc", "", "da853b0d3f88d99b30283a69e6ded6bb", srcPublished},
	{"md4", "abc", "", "a448017aaf21d8525fc10ae87aa6729d", srcPublished},
	{"sha0", "abc", "", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", srcPublished},
	{"whirlpool", "abc", "", "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5", srcPublished},
	{"keccak256", "abc", "", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", srcPublished},
	{"keccak512", "abc", "", "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96", srcPublished},
	{"xxhash32", "abc", "", "32d153ff", srcPublished},
	{"xxhash64", "abc", "", "44bc2cf5ad770999", srcPublished},
	{"murmur3-32", "abc", "", "b3dd93fa", srcPublished},

	// Checksums, cross-checked against Python's zlib and a hand-run FNV-1a.
	{"crc32", "abc", "", "352441c2", srcCrosschecked},
	{"adler32", "abc", "", "024d0127", srcCrosschecked},
	{"fnv1a32", "abc", "", "1a47e90b", srcCrosschecked},
	{"fnv1a64", "abc", "", "e71fa2190541574b", srcCrosschecked},

	// SipHash-2-4, cross-checked against an implementation written separately
	// from the paper. The record carries its own message and round counts.
	{"siphash", "hashsmith", "", "033631dbbb8abefa:2:4:000102030405060708090a0b0c0d0e0f", srcCrosschecked},

	// Regression-only: no independent oracle was available for these, so a pass
	// proves the build still agrees with itself, not that it was ever right.
	{"crc32c", "abc", "", "364b3fb7", srcRegression},
	{"streebog256", "abc", "", "81b4236d62d08c68f30a1e3460b6ff4fcc2618c67062fbc41ed47e13cf19294e", srcRegression},
	{"mysql323", "abc", "", "7cd2b5942be28759", srcRegression},

	// ── Composite constructions (password "hashsmith", salt "Zx9") ─────────
	{"md5-md5pass-salt", "hashsmith", "Zx9", "209a1ebf02b22c103e1b3896b895ecd2", srcCrosschecked},
	{"md5-salt-md5saltpass", "hashsmith", "Zx9", "a5aeb932f0287ad8a1836b0d86afaf72", srcCrosschecked},
	{"md5-salt-md5passsalt", "hashsmith", "Zx9", "2e846cdc2719016d9ee23c059720c4e9", srcCrosschecked},
	{"md5-md5salt-pass", "hashsmith", "Zx9", "893f3cc8bad70b141e5db30be7d9ba05", srcCrosschecked},
	{"md5-md5pass-md5salt", "hashsmith", "Zx9", "bf02be677a7a78ec04bb7c643a4abec3", srcCrosschecked},
	{"md5-sha1salt-md5pass", "hashsmith", "Zx9", "84ae3d9f82d03e46af6bd9c2b5313619", srcCrosschecked},
	{"md5-salt-sha1saltpass", "hashsmith", "Zx9", "1a5145c92871f364197e17bb911e4299", srcCrosschecked},
	{"sha1-salt-pass-salt", "hashsmith", "Zx9", "238ebc97ea594044edf384144bd232bd8701cd9e", srcCrosschecked},
	{"sha1-salt-sha1passsalt", "hashsmith", "Zx9", "c33911d143efbca0be646db445728330dc92a237", srcCrosschecked},
	{"sha1-md5pass-salt", "hashsmith", "Zx9", "ec17b6fa8703c4a828ecf11e8813edbda9494eb7", srcCrosschecked},
	{"sha1-salt-sha1saltsha1pass", "hashsmith", "Zx9", "50612325df8d5aee7963756f9cf2cad85092a7d2", srcCrosschecked},
	{"sha256-sha256pass-salt", "hashsmith", "Zx9", "2d2d6fef33075c2eda14616d8d027805727800304fc034c517fb608a75d729ba", srcCrosschecked},
	{"sha256-md5pass", "hashsmith", "", "35a6e3fc7293a428a3d6c9019f83e2049e100d1cef5adaebb5000fbaf98ef201", srcCrosschecked},
	{"sha256-sha256binpass", "hashsmith", "", "1b966ba4c44c4c629ae2494a34812b7caf6ceaf7ba7949623dfa15d5cd3ccf3c", srcCrosschecked},
	{"md5-pass-pass", "hashsmith", "", "21bb8f8b1c1d616f63edfa05db64d986", srcCrosschecked},
	{"md5-md5pass-pass", "hashsmith", "", "c7be174d24a361c6a7d070968ae3ba9e", srcCrosschecked},
	{"md5-pass-md5pass", "hashsmith", "", "d65f9db8aaadb8808b5d3d80ca9c3038", srcCrosschecked},
	{"md5-md5binpass", "hashsmith", "", "741f5cad0ba709ad9990a5558c8704e7", srcCrosschecked},
	{"sha1-sha1binpass", "hashsmith", "", "662c0d7b4cd66ef4e64da9b7b20d247d37a1d7bd", srcCrosschecked},
	{"sha1-sha1-sha1pass", "hashsmith", "", "9f0ea4b9415ccf2adf31fc8737d7fc47166ce043", srcCrosschecked},
	{"sha512-pass-pass", "hashsmith", "", "0a466c2b72b0012a14b56761716a12ffc75fdd17bfb19d7f2109d1005c03d4694c5cffeb0f516013b25f6b044a87f430265fafc3a3964e37e178092579500037", srcCrosschecked},
	{"md5-salt-md5pass-salt", "hashsmith", "Zx9", "45de7cfe6bd006b8eab2849b5fa009e1", srcCrosschecked},
	{"sha1-salt-md5pass", "hashsmith", "Zx9", "cc3faaa528e2e92d41c83f401d398fba38410bac", srcCrosschecked},
	{"sha512-salt-pass-salt", "hashsmith", "Zx9", "71fe7fe5fe55e18f4114bed4d8af3a7855e78945c8f8dcd40cd336724cab12b7498775a6b25336eb3ea0fba679608b7dad70aa1adf5b3dcf3ded5c6c6cf7c613", srcCrosschecked},

	// ── HMAC variants, cross-checked against Python's hmac ─────────────────
	{"hmac-sha1-saltkey", "abc", "salt", "3950d75670cea3077ff837d684d418da2a1c6f9f", srcCrosschecked},
	{"hmac-sha224", "abc", "salt", "0e6180cf250c0f48c9e5e68e36f2f370e4a23f37cdd396c3b9667edb", srcCrosschecked},
	{"hmac-sha224-saltkey", "abc", "salt", "40009356e31957449805509e49c412f5bbf52977ab4269ea5dd1d840", srcCrosschecked},
	{"hmac-sha384", "abc", "salt", "185751987a7133ac5844279ec20449b4bddd935c60c0ad3139efee3825c63493a9a1e0d5120562fd445c98a7f1a64a14", srcCrosschecked},
	{"hmac-sha384-saltkey", "abc", "salt", "f729472eab43f9aaa98ca68539d0060b3f4e546e938a6b43abdc66fd4b628577423b0ab99885b4b8666743a81bda03a1", srcCrosschecked},
	{"hmac-sha512-saltkey", "abc", "salt", "25635da551d8ad180bab2708fca1f04d3a776d145a7f1910c477c4666a21de2ce3116689a78bf66c6b2cab200eb790663698e2d34fdb641b92927dc7f7804e31", srcCrosschecked},
	{"hmac-sha3_224", "abc", "salt", "229e39b9f914f114524dbfd774d392b8e58401f08d5c8dff609d3d13", srcCrosschecked},
	{"hmac-sha3_224-saltkey", "abc", "salt", "b81fd17c93b5e647dbada9b9d7d2e141b207a16dd4c9fa88d1712958", srcCrosschecked},
	{"hmac-sha3_256", "abc", "salt", "cb40e0c6101c999b39243599528c8897e1280df7f02c1114ace10a0bd2cbe886", srcCrosschecked},
	{"hmac-sha3_256-saltkey", "abc", "salt", "4f74dce9c59b83f157e2621525d911fb9f4634a0cbe4e15c9706a672862d9e67", srcCrosschecked},
	{"hmac-sha3_384", "abc", "salt", "09c2a60fa66a3e3137a9120286294a2f6985bcc2b173eb206e8a9f0bafcb364cdcc1b86e1a74363b1fd9974756c148e6", srcCrosschecked},
	{"hmac-sha3_384-saltkey", "abc", "salt", "da76e573b627052251d97d3a2eb8d546b8008a385daa5bdb1dc1f57d77f943e1fc9091a330ce18a9bf7b4947a27568ee", srcCrosschecked},
	{"hmac-sha3_512", "abc", "salt", "bdd20f129ea38329ca14e7a65d4570b80baf64ffc5a6dbd71ed5153ff1bf2210f76a07cd0cb8bb6df821c11a999ce0390421aa238320c93bd2f0a5301cd3d083", srcCrosschecked},
	{"hmac-sha3_512-saltkey", "abc", "salt", "d8b6ed71413a67aeffabf079688025b27c9c005b8f933d99684b671eb2965f1c2029c7f6e1adba1190ddd277cde6c4237f3a6a1cae3603db65c6f04d45dea124", srcCrosschecked},
	{"hmac-ripemd160", "abc", "salt", "6ad9dab82bc2d24ec301b5f97d9c208756c71ca9", srcCrosschecked},
	{"hmac-ripemd160-saltkey", "abc", "salt", "75c15de70e50ac5b96a36afeb9d9cb2fd83cf33d", srcCrosschecked},

	// ── Nested digests, cross-checked against Python ───────────────────────
	{"sha256-sha256", "abc", "", "dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529dd6b7cbea83f9959c2621b13c", srcCrosschecked},
	{"sha512-sha512", "abc", "", "ee02b3dd5b2c06e4e61888d141998abac194d57692f77ae7a28d748fdf9b9f28f756d980687f7290f1306857edf3fe01f8ebf4626880d49a33e029399cb2d700", srcCrosschecked},
	{"sha3_256-sha3_256", "abc", "", "49a87f9078fe45b5fc410eba4562cb9f23ff7acbdce6793dc1772d200ca1fdf3", srcCrosschecked},

	// ── CRC-64/XZ, cross-checked against a hand-run reflected-ECMA table ───
	// Note this is CRC-64/XZ, not CRC-64/ECMA-182: Go's crc64.Update inverts
	// the register on entry and exit, so init and xorout are all-ones.
	{"crc64", "abc", "", "2cd8094a1a277627", srcCrosschecked},

	// ── Recovered from the repository's existing per-format tests ──────────
	{"aix", "hashcat", "", "{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2", srcPublished},
	{"aspnet-identity", "hashsmith", "", "AAABAgMEBQYHCAkKCwwNDg+Ky5554+IoJfqS5hXxjS0w0jPNKExk4LZOmo818o/5sg==", srcCrosschecked},
	{"atlassian", "hashsmith", "", "{PKCS5S2}ABEiM0RVZneImQCqu8zd7veGLWg0t3824DHQ9UQSJl9E1mxWba+TgfXT8+FCY2s7", srcCrosschecked},
	{"cisco-pix", "hashcat", "", "dRRVnUmUHXOTt9nk", srcPublished},
	{"cisco-asa", "hashcat", "", "02dMBMYkTdC5Ziyp:36", srcPublished},
	{"cisco4", "hashcat", "", "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI", srcPublished},
	{"django", "hashsmith", "", "md5$salty$37795b0102ce7e2ec07898d88690a638", srcCrosschecked},
	{"ethereum", "hashcat", "", "$ethereum$p*1024*38353131353831333338313138363430*a8b4dfe92687dbc0afeb5dae7863f18964241e96b264f09959903c8c924583fc*0a9252861d1e235994ce33dbca91c98231764d8ecb4950015a8ae20d6415b986", srcPublished},
	{"grub2", "hashsmith", "", "grub.pbkdf2.sha512.1000.73616C74792D67727562.CD16B324E198DBDC0B8332A77D72A034D68EDE011F6DBF59DDB80F15E1C1C39342F25AC32DB910201112C836D9FAA0D5C141C21C39CB9BD010B848E445385213", srcCrosschecked},
	{"ike", "hashcat", "", "7a1115b74a1b9d63de62627bdd029aa7a50df83ddbaba88c47d3e51833d21984fb463a2604ba0c82611a11edee7406e1826b2c70410d2797487d1220a4f716d7532fcd73e82b2fd6304f9af5dd1bc0a5dc1eb58bee978f95ffc8b6dc4401d4d2720978f4b0e69ae4dd96e61a1f23a347123aa242f893b33ac74fa234366dc56c:7e599b0168b56608f8a512b68bc7ea47726072ca8e66ecb8792a607f926afc2c3584850773d91644a3186da80414c5c336e07d95b891736f1e88eb05662bf17659781036fa03b869cb554d04689b53b401034e5ea061112066a89dcf8cbe3946e497feb8c5476152c2f8bc0bef4c2a05da51344370682ffb17ec664f8bc07855:419011bd5632fe07:169168a1ac421e4d:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:01110000c0a83965:ee4e517ba0f721798209d04dfcaf965758c4857e:48aada032ae2523815f4ec86758144fa98ad533c:e65f040dad4a628df43f3d1253f821110797a106", srcPublished},
	{"juniper", "netscreen", "", "a$nMf9FkrCIgHGccRAxsBAwxBtDtPHfn", srcPublished},
	{"krb5pa", "hashcat", "", "$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333", srcPublished},
	{"krb5tgs", "hashcat", "", "$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e", srcPublished},
	{"luks", "hashsmith", "", "$luks$1$sha256$aes$xts-plain64$32$dc96fab54243390c27e1ddfd7f9632485d731bbe$6665646362613938373635343332313066656463626139383736353433323130$1$1$3031323334353637383961626364656630313233343536373839616263646566$4$b4a5635f5ae8a9dfe4ef0539a35d6c1d9db8e6389353ff9db11594704e80f6be79fd1609712a5ae0074cfc8be9c9b9179fed889d3d3a78802e887f11ea47dd4d2f4546477c72a40f4dd14c83598d4505935cbbe7efed43810b71c4916284d29ae274b821bf07d4c5ec7be31fae47d4d5431449d2d6dd6763dd61439856441575", srcCrosschecked},
	{"macos", "hashsmith", "", "$ml$1000$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff$1f3e3cbfd3ff3d4020595957d886af6bfd081bfd7706734736d57780340b88806a9f92b21f7609ca2ace446c80d8db7162cee1e0c772f18e779c37ce3f7d2a7782007fcc031dcac973e14604f3632435d84213dd073a7dca187ac47c289a7b04ffe7003c27e8723cc7dc5c878831296485d5ce6eec3c5b00e23aac1db80ea11d", srcCrosschecked},
	{"mysql8", "password", "", "$mysql$A$005*06437A150142644D74187A6A2F0D7971094F2575*48667A67485366745A304F6A487A73704250663465337A7530325157687A51364A384D737554424939702E", srcPublished},
	{"netntlmv1", "hashcat", "", "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920", srcPublished},
	{"netntlmv2", "hashcat", "", "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700", srcPublished},
	{"office", "hashcat", "", "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f", srcPublished},
	{"pbkdf1", "hashcat", "", "PBKDF1:sha1:1000:cGVuZ3VpbmtlZXBlcg==:J4BrIhXDUHNQ9lPPrWKn4V7Of9Y=", srcPublished},
	{"pdf", "hashcat", "", "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000", srcPublished},
	{"passlib-pbkdf2", "hashsmith", "", "$pbkdf2-sha1$1000$c2FsdHk$TX4yNQQZVOCfG5gIIedaYDjifAE", srcCrosschecked},
	{"sha1crypt", "hashcat", "", "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q", srcPublished},
	{"shiro1-sha512", "hashcat", "", "$shiro1$SHA-512$1024$WobJGSjbUhsMdaILomMOdw==$9uptGJ24vzZCqZI55F77N7xjUxGlVrK5aCmAwIrV1vwDmFM4akE6Hmd23Aj8ANLSUdIEkHLZ6SnoitZbOsoQNQ==", srcPublished},
	{"truecrypt", "hashcat", "", tcRIPEMD160AESHeader, srcPublished},
	{"veracrypt", "hashcat", "", "9ecdaf95d05ccf063e8450725b53aa7a1eab419b1b60057a97e8f1ac3c70705c7b298c5443acbdb3507281348fb059cbe7c797877af7fb780454e58595da13aa41ef9346b7601aeac99f4a478d3f0274a9c905d6f46d462d5da920e149f4613e6d80605013b880e9a2c3421fe685beef4916fd09baabacfee14f6d3335675586fb6735484f059fc51f118ae3bd02e888d092b1078a640d235daf8182c8c9d3182359d8a860f00584ce5bfe8f579758ad7196559b6e436e9914a86bad66e237a724999250ed2ded10cabe8f0a3e618194287b2d6e19cf9b83c7b00489876d418460c9c9cbacaa1d26637e0cb6c34df43b17acdd7f6dff18122e8f791b6db5eea14f4cacc4d5e9bd4d8c3c689a1c541e5f650e17788b8e62aa8b77074e0169564af47dc9de64fedf274d373cac7b684cfd03a782da20d0fde4b980c397cbecbf5e15e6effd12940a7f275878c427869be36031eac319dcccc01d0c7de25fd4f10ad4f3f76990e1ec46055529971cb81ce868d9e5179bb7c1be4388b4132e198b3b295a2e96bf777ecfc1e30e263aec5eab79e0c1f6504a93a53c64ade9d51ab11550696c70e19df0c1e956f1c544de73f35f93bfdcb11b0a2f5052840837e34e349d16a8206a2d13d769078356b91828bc1ac077d9ac54a9f2c25c5b3470143c2a8c1309492f356aef20bd289f35333c631d06e79961e98b8e96ec1149977383d3", srcPublished},
	{"werkzeug", "hashsmith", "", "pbkdf2:sha256:1000$salty$f7d97f4feac0e0ce7a184eb5617dc5091632e8cd8933bdde1a4495a9bc208036", srcCrosschecked},
	{"7z", "hashcat", "", "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269", srcPublished},
	{"rar4", "hashcat", "", "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317", srcPublished},

	// ── Real containers built here with zip, gpg and ssh-keygen, then run
	// back through the matching *2smith extractor. ─────────────────────────
	{"zipcrypto", "hashsmith", "", "$zipcrypto$b2$ec7c41d8f99cc1b0e6a61c86", srcCrosschecked},
	{"gpg", "hashsmith", "", "$gpg$3$8$9$35651584$371594bf6a100751$3dc4991bb4427e05866d563b9de98688c46f065d69d847d34df6252200ba402c0109682bf68ad41bb3880cc4a7db97982ea409a53466f9399a8a8c0270f13e0afa7ae0363a26bf8dd0b09da0ca78833f72099ced6ac29212deb79eb0ae9d175ddfc7", srcCrosschecked},
	{"ssh", "hashsmith", "", "$ssh$openssh$aes256-ctr$24$74f3bbf19dece46fd08931e117709df5$fe874351b1518b6eb47cd1e2a3a8dad1", srcCrosschecked},

	// ── Hashcat published example hashes for the newer mode families ───────
	{"blake2b-pass-salt", "hashcat", "", "$BLAKE2$41fcd44c789c735c08b43a871b81c8f617ca43918d38aee6cf8291c58a0b00a03115857425e5ff6f044be7a5bec8536b52d6c9992e21cd43cdca8a55bbf1f5c1:1033", srcPublished},
	{"blake2b-salt-pass", "hashcat", "", "$BLAKE2$f0325fdfc3f82a014935442f7adbc069d4636d67276a85b09f8de368f122cf5195a0b780d7fee709fbf1dcd02ddcb581df84508cf1fb0f3393af1be0565491c6:3301", srcPublished},
	{"blake2b256-pass-salt", "hashcat", "", "$BLAKE2$2b51353016a512b60e587bea98d799c2de243468085ca6cd67f983b2e55bfb67:2353288289", srcPublished},
	{"blake2b256-salt-pass", "hashcat", "", "$BLAKE2$a4cad0b026ed24adf13fb70ec31d35b02751dcb33354e2c9d20ef3f968748501:3601", srcPublished},
	{"crc32-hashcat", "hashcat", "", "c762de4a:00000000", srcPublished},
	{"hmac-blake2s", "hashcat", "", "0d541ae24d30aff2627c4d1a910f766088a64809edb46a05d29649a9b944da6c:1234", srcPublished},
	{"hmac-ripemd320", "hashcat", "", "e740440e7bd65056a90f1aa4eb00e00308a9f1788866b4eacbd46cfc8032301d4e5b3a9d179be044:95454599772294521162217", srcPublished},
	{"hmac-ripemd320-saltkey", "hashcat", "", "345136b13b3a6e52901e2a414efa0cf5fca2fecf8b03279656d3b0f42c30df3006c5ad186494996b:2436077107013929602", srcPublished},
	{"md5-sha1-md5pass", "hashcat", "", "7b4f60b54472980e922280e225150dfa", srcPublished},
	{"murmur64a", "hashcat", "", "ef3014941bf1102d:837163b2348dfae1", srcPublished},
	{"murmur64a-truncated", "hashcat", "", "73f8142b", srcPublished},
	{"murmur64a-zero", "hashcat", "", "73f8142b4326d36a", srcPublished},
	{"murmurhash", "hashcat", "", "b69e7687:05094309", srcPublished},
	{"sha224-sha1pass", "hashcat", "", "10d302483c927df95abba98d69dcd9608365241d1523a8cc5fcbcedc", srcPublished},
	{"sha224-sha224pass", "hashcat", "", "b7d9a0e57e6e94e8b87996b81ffa64b05d237c58fff1d7a4e4fe2a77", srcPublished},
	{"sha512-sha512binpass-salt", "hashcat", "", "c1bade2bd4ebc8db841ac6ab3e0a5035a29619e5b1a6135782b77da5d7cfaccee096f3ddb9ee23b9866378cfc2fb19f2c013fed1b7e1fffd18340a4f39238412:789", srcPublished},
	{"sha512-sha512pass-salt", "hashcat", "", "25d509824028a999f4ee851b5de404bb316b78ae8e974874376484018f58520e082747a7ce9f769bcaccb5f63878356c780f602e23393f12b650a6931e4b9338:21881837027919828109608", srcPublished},
	{"as400-ssha1", "IOIO13", "", "$as400$ssha1$*QTEST1*7ED7D3694D0A2E40A720D41031B456C09124966E", srcPublished},
	{"authme-sha256", "hashcat", "", "$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824", srcPublished},
	{"dane-sha256", "hashcat", "", "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df", srcPublished},
	{"md5-md5salt-md5-md5pass", "hashcat", "", "e13bb4b8e5a98db7277df344aa3363cf:28945624531", srcPublished},
	{"netiq-pbkdf2", "hashcat", "", "$pbkdf2-hmac-sha1$100000$7134180503252384106490944216249411431665011151428170747164626720$990e0c5f62b1384d48cbe3660329b9741c4a8473", srcPublished},
	{"phps", "hashcat", "", "$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f", srcPublished},
	{"samsung-android", "hashcat", "", "0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c", srcPublished},
	{"sspr", "hashcat", "", "$sspr$0$100000$NONE$2c8586ef492e3c3dd3795395507dc14f", srcPublished},
	{"whirlpool-salt-pass-salt", "hashcat", "", "a2c0342a2617026fbaeed01130c826cc3f58242799894b3ecc1abfa811ede03fd712efd14a886af6fa74045502f22c9feb1c45a291cf2d7bbe9bb94c388b6403:deadbeef", srcPublished},

	// ── Further Hashcat application and dual-salt records ──────────────────
	{"md5-salt1-upper-md5-salt2-pass", "hashcat", "", "0e1484eb061b8e9cfd81868bba1dc4a0:229381927:182719643", srcPublished},
	{"md5-triple-dual-salt", "hashcat", "", "c7a971e405313d0ecc22e37e8b2424a1:2316355934:478467", srcPublished},
	{"empirecms", "hashcat", "", "5962d4ada95d6493379cd9c05ce7a376:726620866134417802643053384570:6056291339665060317728572165496183", srcPublished},
	{"cisco-ise", "hashcat", "", "465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1", srcPublished},
	{"fortigate", "hashcat", "", "AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=", srcPublished},
	{"lastpass", "hashcat", "", "02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a", srcPublished},
	{"sap-issha512", "hashcat", "", "{x-isSHA512, 15000}YZH/V2T7zlQMGeWLBarm5Oi3qV9Y8ByXQijD28+bjtLdo7YssXaUBkxMXbS3l4yVlYw97tvYj+vu/L37sg1reDEzODQ4MDY1NzQ1NjQ=", srcPublished},

	// ── Hashcat application/framework records added after the zero-gap pass ─
	{"radmin2", "hashcat", "", "22527bee5c29ce95373c4e0f359f079b", srcPublished},
	{"peoplesoft-token", "hashcat", "", "24eea51b53d02b4c5ff99bcb05a6847fdb2d9308:4f10a0de76e242040c28e9d3dd15c903343489c79765f9118c098c266b9ff505c95bd75bbe406ff3404849eea73930ad17937c0ba6fc3e7bb6d37362941318938b8af96d1292a310b3fd29a67e411ecb10d30247c99183a16951b3859054d4eba9dcd50709c7b21dee836d7ed195cc6b33317aeb557cc56392dc551faa8d5a0fb42212", srcPublished},
	{"java-hashcode", "hashcat", "", "29937c08", srcPublished},
	{"rails-restful-auth", "hashcat", "", "d7d5ea3e09391da412b653ae6c8d7431ec273ea2:238769868762:8962783556527653675", srcPublished},
	{"web2py-pbkdf2", "hashcat", "", "pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c", srcPublished},
	{"flask-session", "hashcat", "", "eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8", srcPublished},
	{"wordpress-bcrypt", "hashcat", "", "$wp$2y$10$lzlQrRRhLSjz486bA9CKHuZRPoKz4uviT251Sq/r5OzKUBbrXwnQW", srcPublished},
	{"krb5db", "hashcat", "", "$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7", srcPublished},

	// ── Hashcat authentication, application, and document records ─────────
	{"mysql-cram", "hashcat", "", "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601", srcPublished},
	{"tacacs-plus", "hashcat", "", "$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006", srcPublished},
	{"apple-secure-notes", "hashcat", "", "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41", srcPublished},
	{"oracle-otm", "hashcat", "", "otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4=", srcPublished},
	{"xmpp-scram", "hashcat", "", "$xmpp-scram$0$4096$45$353835323736323530353932363531393630313632353634313335323434323038393931323138373138343134$6d5b543b985dc6c0645da3c83d114fce121aa51d", srcPublished},
	{"office2016-sheet", "hashcat", "", "$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow==", srcPublished},

	// ── Hashcat protocol and application records ──────────────────────────
	{"postgres-cram", "hashcat", "", "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e", srcPublished},
	{"totp", "hashcat", "", "597056:3600:613004:1234567890:322664:9876543210", srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode0Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode1Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3SHA1Vector, srcCrosschecked},
	{"stellar-wallet", "hashcat", "", "$stellar$YAlIJziURRcBEWUwRSRDWA==$EutMmmcV5Hbf3p1I$rfSAF349RvGKG4R4Z2VCrH9WjNEKjbJa9hpOja9Yn8MwXruuFEMtw47HPn9CYj+JJ5Rb4Z87Wejj1c4fqpbMZHFOnqtQsVAr", srcPublished},
	{"openedge", "hashcat", "", "lebVZteiEsdpkncc", srcPublished},
	{"aws-sig-v4", "hashcat", "", "$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb", srcPublished},

	// ── QNX, SAP CODVN H, and expanded SNMPv3 authentication ─────────────
	{"qnx-md5", "hashcat", "", "@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050", srcPublished},
	{"qnx-sha256", "hashcat", "", "@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604", srcPublished},
	{"qnx-sha512", "hashcat", "", "@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159", srcPublished},
	{"sap-issha1", "hashcat", "", "{x-issha, 1024}BnjXMqcNTwa3BzdnUOf1iAu6dw02NzU4MzE2MTA=", srcPublished},
	{"sap-issha256", "booboo", "", "{x-isSHA256, 3000}UqMnsr5BYN+uornWC7yhGa/Wj0u5tshX19mDUQSlgih6OTFoZjRpMQ==", srcPublished},
	{"sap-issha384", "booboo", "", "{x-isSHA384, 5000}3O/F4YGKNmIYHDu7ZQ7Q+ioCOQi4HRY4yrggKptAU9DtmHigCuGqBiAPVbKbEAfGTzh4YlZLWUM=", srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode2Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode3Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode4Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode5Vector, srcPublished},
	{"snmpv3", "hashcat1", "", snmpV3Mode6Vector, srcPublished},

	// ── Hashcat vendor, messaging, and authentication records ─────────────
	{"telegram-passcode", "hashcat", "", "$telegram$0*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41*25184098058621950709328221838128", srcPublished},
	{"ms-sntp", "hashcat", "", "$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380", srcPublished},
	{"citrix-pbkdf2", "hashcat", "", "5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e", srcPublished},
	{"bcrypt-sha512", "hashcat", "", "$2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJdZNfS3Gy36fvRt56P2jbS", srcPublished},
	{"passlib-bcrypt-sha256", "hashcat", "", "$bcrypt-sha256$v=2,t=2b,r=12$KSOjON/ciJR86a00N5q61.$AmWZucQuHk13FGkQWhgMeiFvBfm2GCy", srcPublished},
	{"anope-sha256", "hashcat", "", "sha256:ab67666e1f91cd38c0ab5bee9c8d2132eca7460354477109a739d4e735b14131:47bcfd0d573653943231df07445da774e5d06465c897ce40578b120bde187e26", srcPublished},

	// ── Hashcat encrypted vendor and authentication records ───────────────
	{"veeam-vbk", "hashcat", "", "$vbk$*54731702769149752741495960625996207399688284541933702394775960978730695504382155223405444342855920150089170058956647576461877712*10000*78cf7df8f1ed8bb50bda1129ec8e6810", srcPublished},
	{"ms-online-account", "hashcat", "", "$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01", srcPublished},
	{"securecrt-v2", "hashcat", "", "S:\"Config Passphrase\"=02:ded7137400e0a1004a12f1708453968ccc270908ba02ab0345c83690d1de3d9937587be66ad2a7fe8cc6cb16ecff02e61ac05e09d4f49f284efd24f6b16d6ae3", srcPublished},
	{"knx-ip-secure", "hashcat", "", "$knx-ip-secure-device-authentication-code$*3033*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41*f927640d9bbe9a4b0b74dd3289ad41ec", srcPublished},
	{"netntlmv2-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700", srcPublished},
	{"teamspeak3", "hashcat", "", "$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA==", srcPublished},

	// ── Hashcat composite and dual-salt records ────────────────────────────
	{"sha1-salt1-pass-salt2", "hashcat", "", "630d2e918ab98e5fad9c61c0e4697654c4c16d73:18463812876898603420835420139870031762867:4449516425193605979760642927684590668549584534278112685644182848763890902699756869283142014018311837025441092624864168514500447147373198033271040848851687108629922695275682773136540885737874252666804716579965812709728589952868736177317883550827482248620334", srcPublished},
	{"sha256-salt-sha256pass", "hashcat", "", "bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:869dc2ed80187919", srcPublished},
	{"sha256-sha256passsalt", "hashcat", "", "ad66bdc0841d7e08d96c03de271ce14e77de078746b535adbf9d4b6ccbf2a517:7218532375810603", srcPublished},
	{"sha1-md5passsalt", "hashcat", "", "aade80a61c6e3cd3cac614f47c1991e0a87dd028:6", srcPublished},
	{"md5-salt1-sha1salt2pass", "hashcat", "", "dc91b5a658ef4b7d859e90742f340e24:708237:d270e9eea5802e346bcaa9b229f37766", srcPublished},
	{"sha256-salt-sha256binpass", "hashcat", "", "5934ea4d670c13a71155faba42056b2525f71bdc9215d31108990c11bf3d98e3:9269771356270099311432765354522635185291064175409115041569", srcPublished},
	{"md5-triple-passsalt-dual", "hashcat", "", "2c749af6c65cf3e82e5837e3056727f5:59331674906582121215362940957615121466283616005471:17254656838978443692786064919357750120910718779182716907569266", srcPublished},
	{"rails-restful-auth-one-round", "hashcat", "", "3999d08db95797891ec77f07223ca81bf43e1be2:5dcc47b04c49d3c8e1b9e4ec367fddeed21b7b85", srcPublished},

	// ── Hashcat seeded checksums and compact vendor records ────────────────
	{"murmur3-seeded", "hashcat", "", "23e93f65:00000000", srcPublished},
	{"crc32c-hashcat", "hashcat", "", "5e23d60f:00000000", srcPublished},
	{"crc64-jones", "hashcat", "", "65c1f848fe38cce6:4260950400318054", srcPublished},
	{"citrix-sha512", "hashcat", "", "2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce", srcPublished},
	{"fortigate256", "hashcat", "", "SH2lpcpFXM5QRlWYwY5vL9+5svfYyb+c79qENpxEoB3NtZpVxKwHjuq/9TH88U=", srcPublished},
	{"umbraco-hmac-sha1", "hashcat", "", "8uigXlGMNI7BzwLCJlDbcKR2FP4=", srcPublished},

	// ── Hashcat application authentication records ────────────────────────
	{"dahua-auth-md5", "hashcat", "", "GRuHbyVp", srcPublished},
	{"besder-auth-md5", "hashcat", "", "GRmHbqVh", srcPublished},
	{"md5-salt-pass-md5pass", "hashcat", "", "86d173f13213d1e48bce9647bdc306d5:8e86a279d6e182b3c811c559e6b15484", srcPublished},
	{"netwitness-sha256", "hashcat", "", "6F48F44C46F5ADC534597687B086278F0AAF7D262ADDB3978562A7D55BBDF467:MDAwMzY1NzYwODI4MQ==", srcPublished},
	{"sha1-salt-user-password", "hashcat", "", "339b5eaa53f28516008e9ca710857d3a4785b6fc:8ca064ff42fcab5a8f0692544b8dd3d3054bd73fe9afaa08c6b6b310538cc9a7:757365726e616d65", srcPublished},
	{"radmin3", "hashcat", "", radmin3PublishedVector, srcPublished},

	// ── Hashcat legacy, DNS, and known-plaintext cipher records ────────────
	{"oracle-h", "hashcat", "", "792FCB0AE31D8489:7284616727", srcPublished},
	{"ipmi-md5", "admin", "", "08b017f3628b9835c748521e412429c9:f3450000df540000cdd981b0b3441be8774a61e69321291891a29a0c5fdac3f06194bd2c29fa5246000000000000000000000000000000001400", srcPublished},
	{"krb5pa", "hashcat", "", "$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835", srcPublished},
	{"dnssec-nsec3", "hashcat", "", "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1", srcPublished},
	{"skip32", "hashcat!!!", "", "c9350366:44630464", srcPublished},
	{"aes128-ecb-nokdf", "hashcat", "", "e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724", srcPublished},
	{"aes192-ecb-nokdf", "hashcat", "", "2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320", srcPublished},
	{"aes256-ecb-nokdf", "hashcat", "", "264a4248c9522cb74d33fe26cb596895:61270210011294880287232432636227", srcPublished},
	{"md5-salt-pass", "hashcat", "", "e983672a03adcc9767b24584338eb378:00", srcPublished},

	// ── Remaining hashable types ───────────────────────────────────────────
	// bcrypt is the published OpenWall vector; postgres is cross-checked against
	// Python's md5. The rest had no independent oracle available here, so they
	// are regression-only: a pass shows the build still agrees with itself.
	{"bcrypt", "password", "", "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe", srcPublished},
	{"postgres", "secretpw", "testuser", "md51798e3a2215a571e6f8d2b4bf2db9db5", srcCrosschecked},
	{"mssql2000", "secretpw", "", "503402E1C64BD514F4CFE4082E4BA1B06B5A939F", srcRegression},
	{"mssql2005", "hashcat", "", "0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325", srcPublished},
	{"mssql2012", "hashcat", "", "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1", srcPublished},
	{"streebog512", "secretpw", "", "5ba3ca7887326884b55f8f422ac1f0f0921af86b79724755a8e60c1c2a25e77471bef28a205176a1ade88922c2c636f457298b93d3d9390e266a3f2d0a691080", srcRegression},
	{"argon2", "secretpw", "", "$argon2id$v=19$m=102400,t=2,p=8$ASNFZ4mrze8$yIAnV4Et+Xm1JEUGQXyTKomcQaV1AmA2RumwR4wxWy8", srcRegression},
	{"ldap-pbkdf2", "secretpw", "", "{PBKDF2_SHA256}AAAgAKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6teSuIJLfiaaXQ+9Lg6HFwOqIY4E90fson7SzcEGLcNl7Gz7kcDwEqL/erfHZVKBhT63PSPV16tcCzAq9vBsQ/BH47aEHN5rU+SHtRwmGhTZ2P/5SWTR0ggzO1s6w7w23Anojc3ArXHvPk1THbJQnm2g8gozhRtXrHY9GWYPCd3jZJbZGa51exqeIlO1YDEymmKNyXanvTLcTC2WQxTemMI/bZUgh9Cpi9+3DtyaBKmQNCzZY0burrXZlCMFdzZXHEEZTTt6DBSfv0f/QWecTLcjyI2NfRwUEFP6KrlBDZoHfKcSvGczO7foV2+EsohteoHFW2k6Bq6MNZcmMuU/Yl4", srcRegression},

	// ── Hashcat published vectors for the bcrypt-of-digest and extended
	// composite families ──────────────────────────────────────────────────
	{"bcrypt-md5", "hashcat", "", "$2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru", srcPublished},
	{"bcrypt-sha1", "hashcat", "", "$2a$05$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXePGka4WGFv.86I45AEjmO", srcPublished},
	{"bcrypt-sha256", "hashcat", "", "$2b$10$FxDtpTNaL303lLcWtd6LFO2U6Gc63VJ07qycHcfqbQQ71GhO/qSzu", srcPublished},
	{"md5-md5-md5pass-salt", "hashcat", "", "a0ab79f9e2b5a4434d2da61673b56362:1234", srcPublished},
	{"md5-md5passsalt", "hashcat", "", "0127eecea3120e34c8934ba3b72a390a:0", srcPublished},
	{"md5-sha1pass-salt", "hashcat", "", "bc8319c0220bff8a0d7f5d703114a725:34659348756345251", srcPublished},
	{"md5-sha1passsalt", "hashcat", "", "34ebbba3e5c98f6253c160eae53da092:6224378456121050285", srcPublished},
	{"md5-sha1saltpass", "hashcat", "", "df0e9ede5b6c7d1f1b47199f86029002:59132809201799180722359939692710461886", srcPublished},
	{"sha1-sha1pass-salt", "hashcat", "", "9138d472fce6fe50e2a32da4eec4ecdc8860f4d5:hashcat1", srcPublished},
	{"sha1-sha1saltpasssalt", "hashcat", "", "05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020", srcPublished},

	// ── Hashcat compatibility expansion ──────────────────────────────────
	{"keccak224", "hashcat", "", "e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636", srcPublished},
	{"keccak384", "hashcat", "", "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701", srcPublished},
	{"sha1-md5-md5pass", "hashcat", "", "888a2ffcb3854fba0321110c5d0d434ad1aa2880", srcPublished},
	{"hmac-streebog256", "hashcat", "", "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337", srcPublished},
	{"hmac-streebog256-saltkey", "hashcat", "", "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337", srcPublished},
	{"hmac-streebog512", "hashcat", "", "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337", srcPublished},
	{"hmac-streebog512-saltkey", "hashcat", "", "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337", srcPublished},
	{"arubaos", "hashcat", "", "5387280701327dc2162bdeb451d5a465af6d13eff9276efeba", srcPublished},
	{"sha1-cx", "hashcat", "", "fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702", srcPublished},
	{"dovecot-cram-md5", "hashcat", "", "{CRAM-MD5}5389b33b9725e5657cb631dc50017ff1535ce4e2a1c414009126506fc4327d0d", srcPublished},
	{"sm3crypt", "hashcat", "", "$sm3$KTTUB40dW4mRyRFd$ul2xLiIY3FJtbo8sv1R93sAYCkxQCH/6rmS1kD5vJYA", srcPublished},

	// ── Hashcat cipher and password-state expansion ───────────────────────
	{"des-plaintext", "hashcat1", "", "53b325182924b356:1412781058343178", srcPublished},
	{"3des-plaintext", "hashcat1hashcat1hashcat1", "", "4c29eea59d8db1e7:7428288455525516", srcPublished},
	{"chacha20", "hashcat_hashcat_hashcat_hashcat_", "", "$chacha20$*0400000000000003*16*0200000000000001*5152535455565758*6b05fe554b0bc3b3", srcPublished},
	{"tripcode", "hashcat", "", "pfaRCwDe0U", srcPublished},
	{"mojolicious", "hashcat", "", "mojolicious=abc--85d455b37bc3d8672908fde9e802cc3294d7db7ad0d63768305d105a948fb823", srcCrosschecked},
	{"blockchain-second", "hashcat", "", "YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc=", srcPublished},
	{"dcc-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "c896b3c6963e03c86ade3a38370bbb09:54161084332", srcPublished},
	{"dcc2-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626", srcPublished},

	// ── Hashcat state and legacy-record expansion ─────────────────────────
	{"md5-salt1-pass-salt2", "hashcat", "", "036a81bc84e01700faf965c3caaa3954:0243402616975530019305541949338903179746132451440267505028190519468680111713847350899833009965414425621884797638402856957040435715380438220464016:0757380776148401126145133134435506200715895167468508855794708942913462135276430452032928239699197100625556660484150983610760766285767453357925167463064045123083116191440783332986105343359475417787249790516137833723344398087127577224833364437305770807742238", srcPublished},
	{"rc4-dropn", "hashc", "", "$rc4$40$0$e9a41693b759cf88929ca31203694f$0$48656c6c6f", srcPublished},
	{"blockchain-legacy", "hashcat", "", "$blockchain$269$0349575305940509451603791869345994679e29d1618f26ed65ee15ad65d1af046f51ffcfbfa82dcccea07bb0f0fff725af53b96910646440b361453addc5caeb2a09479dc6cce3a1ebf138e2649689ab286ba2db6bd5edef310cac8f9386f002a534e9346cdc61bd0e21ca738eb2418a8158c83a43517981c43d8792cad6f290cbf40d5a3c1bb20283fcb44c59cae2dc90c898dbc4e960ca666653a08d90471610a8b9bf590752e8d8bee27e7aa58d015324dae83c87a46384ed8f947e37e65d4572018b5bfd8fd8ea70df777c8b692bc613ccb528356d1844490ac2b3be2dd8927fbf1aabf9b6cedec39742ed92a03220f4468bd32c1eed5d5c3c3aa0be459e06466c94991df97f335bd661", srcPublished},
	{"krb5tgs-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a", srcPublished},
	{"krb5asrep-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac", srcPublished},
	{"phpass-md5", "hashcat", "", "$H$9ZtU3uM7Twc8X53ImNRhaec4b3QHJ91", srcPublished},
	{"symfony-legacy", "hashcat", "", "e65e9e4f3cd2f28dd8f18de72a465b3a8cd982ba615fada61842ecea05ca0c9c:3fd6486e7c9d4eb920275412198bb7f8ed7eacd53ba953dd50f1e481952c15b5", srcPublished},

	// ── Hashcat wallet and wireless expansion ─────────────────────────────
	{"ethereum-presale", "hashcat", "", "$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593", srcPublished},
	{"wpa-pmkid", "hashcat!", "", "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a", srcPublished},
	{"wpa-pmk", "5b13d4babb3714ccc62c9f71864bc984efd6a55f237c7a87fc2151e1ca658a9d", "", "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4", srcPublished},
	{"wpa-pmk", "88f43854ae7b1624fc2ab7724859e795130f4843c7535729e819cf92f39535dc", "", "WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*accd10fb464e*686173686361742d6573736964***", srcPublished},
	{"wpa-hccapx", "hashcat!", "", hccapxHashcatSelfTest, srcPublished},
	{"wpa-hccapx-pmk", "7f620a599c445155935a35634638fa67b4aafecb92e0bd8625388757a63c2dda", "", hccapxHashcatSelfTest, srcPublished},
	{"netntlmv1-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "", "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920", srcPublished},
	{"krb5db", "hashcat", "", "$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e", srcPublished},
	{"aescrypt", "hashcat", "", "$aescrypt$1*efc648908ca7ec727f37f3316dfd885c*eff5c87a35545406a57b56de57bd0554*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e", srcPublished},
	{"multibit-key", "hashcat", "", "$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de", srcPublished},
	{"terra-wallet", "hashcat", "", "67445496c838e96c1424a8dae4b146f0fc247c8c34ef33feffeb1e4412018512wZGtBMeN84XZE2LoOKwTGvA4Ee4m7PR1lDGIdWUV6OSUZKRiKFx9tlrnZLt8r8OfOzbwUS2a2Uo+nrrP6F85fh4eHstwPJw0KwzHWB8br58=", srcPublished},
}
