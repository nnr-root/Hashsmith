# Recognition accuracy baseline

Date: 2026-09-05. Base commit: `62e2617` (working directly on `main`, per
Task 15's instructions). This note records what
`cmd/hashsmith/recognition_test.go` measured, verbatim from its `-v` output,
without rounding in Hashsmith's favour. Numbers below are quoted after this
task's own fixes to `mssql2012`, `cisco4` and `ripemd320` detection (see
"What was fixed" below) — this is the number the ratchet in
`recognition_test.go` is set against, not a pre-fix number.

## Recognition rate

```
recognition: 272/502 = 54.2%
```

As a fraction: 272/502. As an exact percentage: 54.18326693227091...%, which
Go's `%.1f` rounds to the 54.2% printed above (not rounded up by hand — that
is the test's own formatting). Before any fix in this task, the first
measured run (Step 2, before touching any code) was 271/502 = 53.98...%,
which `%.1f` printed as 54.0%. `mssql2012` was the only one of this task's
three fixes that moved this number (`cisco4` and `ripemd320` are recognized
for cracking now but stay at `TierShape`/"possible" confidence — see below —
so they do not change the count of certain/likely candidates): fixing it
alone moved the rate from 271/502 to 272/502.

`recognitionFloor` is now set to `272.0/502.0 - 0.01` (a computed constant,
not a hand-rounded literal), so it ratchets against regression from the
measured 54.18% down to no lower than 53.18%.

## Formats not recognized at certain/likely (209)

Verbatim from the test log:

```
3des-plaintext adler32 bcrypt-md5 bcrypt-sha1 bcrypt-sha256 bcrypt-sha512
besder-auth-md5 blake2b blake2b256 blake2b384 blake2s cisco-ise cisco4 crc32
crc32c crc64 dahua-auth-md5 dane-sha256 dcc-nt dcc2-nt des-plaintext descrypt
empirecms fnv1a32 fnv1a64 half-md5 hmac-blake2s hmac-md5 hmac-md5-saltkey
hmac-ripemd160 hmac-ripemd160-saltkey hmac-ripemd320 hmac-ripemd320-saltkey
hmac-sha1 hmac-sha1-saltkey hmac-sha224 hmac-sha224-saltkey hmac-sha256
hmac-sha256-saltkey hmac-sha384 hmac-sha384-saltkey hmac-sha3_224
hmac-sha3_224-saltkey hmac-sha3_256 hmac-sha3_256-saltkey hmac-sha3_384
hmac-sha3_384-saltkey hmac-sha3_512 hmac-sha3_512-saltkey hmac-sha512
hmac-sha512-saltkey hmac-streebog256 hmac-streebog256-saltkey hmac-streebog512
hmac-streebog512-saltkey java-hashcode keccak224 keccak256 keccak384 keccak512
lm luks-ripemd160-aes luks-ripemd160-serpent luks-ripemd160-twofish
luks-sha1-aes luks-sha1-serpent luks-sha1-twofish luks-sha256-aes
luks-sha256-serpent luks-sha256-twofish luks-sha512-aes luks-sha512-serpent
luks-sha512-twofish md2 md4 md5-md5 md5-md5-md5 md5-md5binpass
md5-md5pass-md5salt md5-md5pass-pass md5-md5pass-salt md5-md5salt-md5pass
md5-md5salt-pass md5-pass-md5pass md5-pass-pass md5-salt-md5pass
md5-salt-md5pass-salt md5-salt-md5passsalt md5-salt-md5saltpass
md5-salt-pass-salt md5-salt-sha1saltpass md5-salt1-pass-salt2
md5-salt1-sha1salt2pass md5-salt1-upper-md5-salt2-pass md5-sha1
md5-sha1-md5pass md5-sha1pass-md5pass-sha1pass md5-sha1salt-md5pass
md5-triple-dual-salt md5-triple-passsalt-dual md5-upper-md5 md5-utf16le
mssql2000 murmur3-32 murmur64a-truncated murmur64a-zero mysql323 mysql41
netntlmv1-nt netntlmv2-nt office-old openedge oracle11g oracle12c peoplesoft
radmin2 ripemd128 ripemd160 ripemd256 ripemd320 samsung-android sha0 sha1-md5
sha1-md5-md5pass sha1-md5pass-salt sha1-salt-md5pass sha1-salt-pass-salt
sha1-salt-sha1pass sha1-salt-sha1passsalt sha1-salt-sha1saltsha1pass sha1-sha1
sha1-sha1-sha1pass sha1-sha1binpass sha1-utf16le sha224 sha224-sha1pass
sha224-sha224pass sha256-md5pass sha256-salt-pass-salt sha256-salt-uppersha1pass
sha256-salt-utf16lepass sha256-sha256 sha256-sha256binpass sha256-sha256pass-salt
sha256-utf16le sha384 sha384-utf16le sha3_224 sha3_256 sha3_256-sha3_256
sha3_384 sha3_512 sha512-pass-pass sha512-salt-pass sha512-salt-pass-salt
sha512-sha512 sha512-sha512binpass sha512-utf16le sha512_224 sha512_256
shake128-256 shake256-512 sm3 streebog256 streebog512 tripcode truecrypt
truecrypt-ripemd160 truecrypt-ripemd160-boot-xts1024
truecrypt-ripemd160-boot-xts1536 truecrypt-ripemd160-boot-xts512
truecrypt-ripemd160-xts1024 truecrypt-ripemd160-xts1536 truecrypt-sha512
truecrypt-sha512-xts1024 truecrypt-sha512-xts1536 truecrypt-whirlpool
truecrypt-whirlpool-xts1024 truecrypt-whirlpool-xts1536 veracrypt
veracrypt-ripemd160 veracrypt-ripemd160-boot-xts1024
veracrypt-ripemd160-boot-xts1536 veracrypt-ripemd160-boot-xts512
veracrypt-ripemd160-xts1024 veracrypt-ripemd160-xts1536 veracrypt-sha256
veracrypt-sha256-boot-xts1024 veracrypt-sha256-boot-xts1536
veracrypt-sha256-boot-xts512 veracrypt-sha256-xts1024 veracrypt-sha256-xts1536
veracrypt-sha512 veracrypt-sha512-xts1024 veracrypt-sha512-xts1536
veracrypt-streebog512 veracrypt-streebog512-boot-xts1024
veracrypt-streebog512-boot-xts1536 veracrypt-streebog512-boot-xts512
veracrypt-streebog512-xts1024 veracrypt-streebog512-xts1536 veracrypt-whirlpool
veracrypt-whirlpool-xts1024 veracrypt-whirlpool-xts1536 whirlpool
wpa-hccapx-pmk wpa-pmk xxhash32 xxhash64
```

Count: 209.

Note that `cisco4` and `ripemd320` remain on this list even after being
fixed for auto-detection (see below): both are now correctly recognized at
`TierShape` (length + alphabet only, no distinguishing marker), which by
design (`internal/hashid/confidence.go`) can reach at best "possible"
confidence unless it is also both rivalled and dominantly prevalent. Neither
is, so neither reaches "certain"/"likely". Claiming otherwise for either
would mean assigning a tier stronger than the actual evidence, which is
exactly the kind of overclaim this task is measuring honestly against.

## Vectors whose own type is not among `detectHashTypes`' candidates

Before any fix in this task: **197**. After fixing `mssql2012`, `cisco4` and
`ripemd320` (see below): **194** — `cisco4` and `ripemd320` are correctly
absent from the post-fix list; `mssql2012` was already absent (it was fixed
first, at 197 → 196, before `cisco4` and `ripemd320` brought it to 194).

Verbatim from `go test -run TestEveryVectorIsDetectableForCracking -v` after
all three fixes (type and the first 40 chars of its own vector target, the
test's own truncation, one per line; two duplicate-looking lines for the
same type are two different vectors sharing a type, e.g. two independent
`truecrypt-ripemd160-boot-xts1024` vectors):

```
3des-plaintext (4c29eea59d8db1e7:7428288455525516)
adler32 (024d0127)
bcrypt-md5 ($2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12y)
bcrypt-sha1 ($2a$05$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXe)
bcrypt-sha256 ($2b$10$FxDtpTNaL303lLcWtd6LFO2U6Gc63VJ07)
bcrypt-sha512 ($2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJd)
crc32 (352441c2)
crc32c (364b3fb7)
crc64 (2cd8094a1a277627)
dane-sha256 (127e6fbfe24a750e72930c220a8e138275656b8e)
dcc-nt (c896b3c6963e03c86ade3a38370bbb09:5416108)
dcc2-nt ($DCC2$10240#6848#e2829c8af2232fa53797e2f)
des-plaintext (53b325182924b356:1412781058343178)
empirecms (5962d4ada95d6493379cd9c05ce7a376:7266208)
fnv1a32 (1a47e90b)
fnv1a64 (e71fa2190541574b)
hmac-blake2s (0d541ae24d30aff2627c4d1a910f766088a64809)
hmac-md5 (32b4db8a8185e0bdfe5b3b343d3a894a)
hmac-md5-saltkey (d711a5cc511fb1a7d5f19d7c911aff2d)
hmac-ripemd160 (6ad9dab82bc2d24ec301b5f97d9c208756c71ca9)
hmac-ripemd160-saltkey (75c15de70e50ac5b96a36afeb9d9cb2fd83cf33d)
hmac-ripemd320 (e740440e7bd65056a90f1aa4eb00e00308a9f178)
hmac-ripemd320-saltkey (345136b13b3a6e52901e2a414efa0cf5fca2fecf)
hmac-sha1 (99895f95046de53f03060cea36c24f7075cc0e54)
hmac-sha1-saltkey (3950d75670cea3077ff837d684d418da2a1c6f9f)
hmac-sha224 (0e6180cf250c0f48c9e5e68e36f2f370e4a23f37)
hmac-sha224-saltkey (40009356e31957449805509e49c412f5bbf52977)
hmac-sha256 (fbf087a3135b4af8615b2836534788c59b55acdb)
hmac-sha256-saltkey (5031dfb5b067c1d64e70ad09acb9c5421c194ebb)
hmac-sha384 (185751987a7133ac5844279ec20449b4bddd935c)
hmac-sha384-saltkey (f729472eab43f9aaa98ca68539d0060b3f4e546e)
hmac-sha3_224 (229e39b9f914f114524dbfd774d392b8e58401f0)
hmac-sha3_224-saltkey (b81fd17c93b5e647dbada9b9d7d2e141b207a16d)
hmac-sha3_256 (cb40e0c6101c999b39243599528c8897e1280df7)
hmac-sha3_256-saltkey (4f74dce9c59b83f157e2621525d911fb9f4634a0)
hmac-sha3_384 (09c2a60fa66a3e3137a9120286294a2f6985bcc2)
hmac-sha3_384-saltkey (da76e573b627052251d97d3a2eb8d546b8008a38)
hmac-sha3_512 (bdd20f129ea38329ca14e7a65d4570b80baf64ff)
hmac-sha3_512-saltkey (d8b6ed71413a67aeffabf079688025b27c9c005b)
hmac-sha512 (ef1d6c5a22a8768e729685351d67e81a850a846a)
hmac-sha512-saltkey (25635da551d8ad180bab2708fca1f04d3a776d14)
hmac-streebog256 (0f71c7c82700c9094ca95eee3d804cc283b538be)
hmac-streebog256-saltkey (d5c6b874338a492ac57ddc6871afc3c70dcfd264)
hmac-streebog512 (be4555415af4a05078dcf260bb3c0a35948135df)
hmac-streebog512-saltkey (bebf6831b3f9f958acb345a88cb98f30cb0374cf)
java-hashcode (29937c08)
lm (299bd128c1101fd6)
luks-ripemd160-aes ($luks$1$ripemd160$aes$xts-plain64$32$ef2)
luks-ripemd160-serpent ($luks$1$ripemd160$serpent$xts-plain64$32)
luks-ripemd160-twofish ($luks$1$ripemd160$twofish$xts-plain64$32)
luks-sha1-aes ($luks$1$sha1$aes$xts-plain64$32$317296de)
luks-sha1-serpent ($luks$1$sha1$serpent$xts-plain64$32$3172)
luks-sha1-twofish ($luks$1$sha1$twofish$xts-plain64$32$3172)
luks-sha256-aes ($luks$1$sha256$aes$xts-plain64$32$8d94d5)
luks-sha256-serpent ($luks$1$sha256$serpent$xts-plain64$32$8d)
luks-sha256-twofish ($luks$1$sha256$twofish$xts-plain64$32$8d)
luks-sha512-aes ($luks$1$sha512$aes$xts-plain64$32$218d9c)
luks-sha512-serpent ($luks$1$sha512$serpent$xts-plain64$32$21)
luks-sha512-twofish ($luks$1$sha512$twofish$xts-plain64$32$21)
md5-md5 (a936af92b0ae20b1ff6c3347a72e5fbe)
md5-md5-md5 (9882d0778518b095917eb589f6998441)
md5-md5binpass (741f5cad0ba709ad9990a5558c8704e7)
md5-md5pass-md5salt (bf02be677a7a78ec04bb7c643a4abec3)
md5-md5pass-pass (c7be174d24a361c6a7d070968ae3ba9e)
md5-md5pass-salt (209a1ebf02b22c103e1b3896b895ecd2)
md5-md5salt-md5pass (d9afd016defaf2c9cc7ec7d91b674b09)
md5-md5salt-pass (893f3cc8bad70b141e5db30be7d9ba05)
md5-pass-md5pass (d65f9db8aaadb8808b5d3d80ca9c3038)
md5-pass-pass (21bb8f8b1c1d616f63edfa05db64d986)
md5-salt-md5pass (b20c905b199b3e72785c8c7708aeddfb)
md5-salt-md5pass-salt (45de7cfe6bd006b8eab2849b5fa009e1)
md5-salt-md5passsalt (2e846cdc2719016d9ee23c059720c4e9)
md5-salt-md5saltpass (a5aeb932f0287ad8a1836b0d86afaf72)
md5-salt-pass-salt (903d7e353140c6e09b6bcf38a574594f)
md5-salt-sha1saltpass (1a5145c92871f364197e17bb911e4299)
md5-salt1-pass-salt2 (036a81bc84e01700faf965c3caaa3954:0243402)
md5-salt1-sha1salt2pass (dc91b5a658ef4b7d859e90742f340e24:708237:)
md5-salt1-upper-md5-salt2-pass (0e1484eb061b8e9cfd81868bba1dc4a0:2293819)
md5-sha1 (288496df99b33f8f75a7ce4837d1b480)
md5-sha1-md5pass (7b4f60b54472980e922280e225150dfa)
md5-sha1pass-md5pass-sha1pass (743aaa6545dc3fec867bd2d9eaed4823)
md5-sha1salt-md5pass (84ae3d9f82d03e46af6bd9c2b5313619)
md5-triple-dual-salt (c7a971e405313d0ecc22e37e8b2424a1:2316355)
md5-triple-passsalt-dual (2c749af6c65cf3e82e5837e3056727f5:5933167)
md5-upper-md5 (b8c385461bb9f9d733d3af832cf60b27)
md5-utf16le (2303b15bfa48c74a74758135a0df1201)
mssql2000 (503402E1C64BD514F4CFE4082E4BA1B06B5A939F)
murmur3-32 (b3dd93fa)
murmur64a-truncated (73f8142b)
murmur64a-zero (73f8142b4326d36a)
mysql41 (fcf7c1b8749cf99d88e5f34271d636178fb5d130)
netntlmv1-nt (::5V4T:ada06359242920a500000000000000000)
netntlmv2-nt (0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fb)
office-old ($oldoffice$0*550450616474566888604112180)
openedge (lebVZteiEsdpkncc)
peoplesoft (2uCd2T/LX41DjVEwFi9KoRahpX4=)
radmin2 (22527bee5c29ce95373c4e0f359f079b)
ripemd128 (c14a12199c66e4ba84636b0f69144c77)
ripemd256 (afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7d)
samsung-android (0223b799d526b596fe4ba5628b9e65068227e68e)
sha1-md5 (92d85978d884eb1d99a51652b1139c8279fa8663)
sha1-md5-md5pass (888a2ffcb3854fba0321110c5d0d434ad1aa2880)
sha1-md5pass-salt (ec17b6fa8703c4a828ecf11e8813edbda9494eb7)
sha1-salt-md5pass (cc3faaa528e2e92d41c83f401d398fba38410bac)
sha1-salt-pass-salt (238ebc97ea594044edf384144bd232bd8701cd9e)
sha1-salt-sha1pass (1498106ecd17f9f820d38a7578ba444d33351e54)
sha1-salt-sha1passsalt (c33911d143efbca0be646db445728330dc92a237)
sha1-salt-sha1saltsha1pass (50612325df8d5aee7963756f9cf2cad85092a7d2)
sha1-sha1 (3db9184f5da4e463832b086211af8d2314919951)
sha1-sha1-sha1pass (9f0ea4b9415ccf2adf31fc8737d7fc47166ce043)
sha1-sha1binpass (662c0d7b4cd66ef4e64da9b7b20d247d37a1d7bd)
sha1-utf16le (b9798556b741befdbddcbf640d1dd59d19b1e193)
sha224-sha1pass (10d302483c927df95abba98d69dcd9608365241d)
sha224-sha224pass (b7d9a0e57e6e94e8b87996b81ffa64b05d237c58)
sha256-md5pass (35a6e3fc7293a428a3d6c9019f83e2049e100d1c)
sha256-salt-pass-salt (e96b01deda9eee797d01383bb9e611f755cdc2f3)
sha256-salt-uppersha1pass (1a93033337810e3624427730236f76fcd3ecbb91)
sha256-salt-utf16lepass (7debd89b3b350568a11e74d36e26b85b7cc39548)
sha256-sha256 (dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529d)
sha256-sha256binpass (1b966ba4c44c4c629ae2494a34812b7caf6ceaf7)
sha256-sha256pass-salt (2d2d6fef33075c2eda14616d8d02780572780030)
sha256-utf16le (9e9283e633f4a7a42d3abc93701155be8afe5660)
sha384-utf16le (48e61d68e93027fae35d405ed16cd01b6f1ae662)
sha3_256-sha3_256 (49a87f9078fe45b5fc410eba4562cb9f23ff7acb)
sha512-pass-pass (0a466c2b72b0012a14b56761716a12ffc75fdd17)
sha512-salt-pass (976b451818634a1e2acba682da3fd6efa72adf8a)
sha512-salt-pass-salt (71fe7fe5fe55e18f4114bed4d8af3a7855e78945)
sha512-sha512 (ee02b3dd5b2c06e4e61888d141998abac194d576)
sha512-sha512binpass (67744bf0ad8a06ccc73359acf47a469430958dc9)
sha512-utf16le (79bba09eb9354412d0f2c037c22a777b8bf549ab)
tripcode (pfaRCwDe0U)
truecrypt (87914967f14737a67fb460f27b8aeb81de2b41bf)
truecrypt-ripemd160 ($truecrypt$87914967f14737a67fb460f27b8ae)
truecrypt-ripemd160-boot-xts1024 ($truecrypt$debcc3e74a7b2acb4c7eaa4ac86fd)
truecrypt-ripemd160-boot-xts1024 ($truecrypt$debcc3e74a7b2acb4c7eaa4ac86fd)
truecrypt-ripemd160-boot-xts1536 ($truecrypt$5e6628907291b0b74a4f43a23fb06)
truecrypt-ripemd160-boot-xts1536 ($truecrypt$5e6628907291b0b74a4f43a23fb06)
truecrypt-ripemd160-boot-xts512 ($truecrypt$2b5da9924119fde5270f712ba3c3e)
truecrypt-ripemd160-boot-xts512 ($truecrypt$2b5da9924119fde5270f712ba3c3e)
truecrypt-ripemd160-xts1024 ($truecrypt$d6e1644acd373e6fdb8ccaaeab0c4)
truecrypt-ripemd160-xts1536 ($truecrypt$3916e924d246e5ceb17b140211fff)
truecrypt-sha512 ($truecrypt$5ebff6b4050aaa3374f9946166a9c)
truecrypt-sha512-xts1024 ($truecrypt$9f207bec0eded18a1b2e324d4f05d)
truecrypt-sha512-xts1536 ($truecrypt$721a7f40d2b88de8e11f1a203b04f)
truecrypt-whirlpool ($truecrypt$cf53d4153414b63285e701e52c2d9)
truecrypt-whirlpool ($truecrypt$cf53d4153414b63285e701e52c2d9)
truecrypt-whirlpool-xts1024 ($truecrypt$e9e503972b72dee996b0bfced2df0)
truecrypt-whirlpool-xts1024 ($truecrypt$e9e503972b72dee996b0bfced2df0)
truecrypt-whirlpool-xts1536 ($truecrypt$de7d6725cc4c910a7e96307df69d4)
truecrypt-whirlpool-xts1536 ($truecrypt$de7d6725cc4c910a7e96307df69d4)
veracrypt (9ecdaf95d05ccf063e8450725b53aa7a1eab419b)
veracrypt-ripemd160 ($veracrypt$531aca1fa6db5118506320114cb11)
veracrypt-ripemd160-boot-xts1024 ($veracrypt$a3c0fa44ec59bf7a3eed64bf70b8a)
veracrypt-ripemd160-boot-xts1024 (a3c0fa44ec59bf7a3eed64bf70b8a60623664503)
veracrypt-ripemd160-boot-xts1536 ($veracrypt$1a8c0135fa94567aa866740cb27c5)
veracrypt-ripemd160-boot-xts1536 (1a8c0135fa94567aa866740cb27c5b9763c95be3)
veracrypt-ripemd160-boot-xts512 ($veracrypt$528c2997054ce1d22cbc5233463df)
veracrypt-ripemd160-boot-xts512 (528c2997054ce1d22cbc5233463df8119a0318ab)
veracrypt-ripemd160-xts1024 ($veracrypt$531aca1fa6db5118506320114cb11)
veracrypt-ripemd160-xts1536 ($veracrypt$531aca1fa6db5118506320114cb11)
veracrypt-sha256 ($veracrypt$b8a19a544414e540172595aef79e6)
veracrypt-sha256-boot-xts1024 ($veracrypt$6bb6eef1af55eb2b2849e1fc9c90c)
veracrypt-sha256-boot-xts1024 (6bb6eef1af55eb2b2849e1fc9c90c08f705010ef)
veracrypt-sha256-boot-xts1536 ($veracrypt$f95b222552195378a228d932f7df3)
veracrypt-sha256-boot-xts1536 (f95b222552195378a228d932f7df38ca459b6d81)
veracrypt-sha256-boot-xts512 ($veracrypt$c8a5f07efc320ecd797ac2c5b911b)
veracrypt-sha256-boot-xts512 (c8a5f07efc320ecd797ac2c5b911b0f7ee688f85)
veracrypt-sha256-xts1024 ($veracrypt$1c3197f32dc5b72b4d60474a7a43a)
veracrypt-sha256-xts1536 ($veracrypt$f421bdc1087b8319c12d84a680cea)
veracrypt-sha512 ($veracrypt$2be25b279d8d2694e0ad1e5049902)
veracrypt-sha512-xts1024 ($veracrypt$37e6db10454a5d74c1e75eca0bc8a)
veracrypt-sha512-xts1536 ($veracrypt$d44f26d1742260f88023d825729cc)
veracrypt-streebog512 ($veracrypt$444ec71554f0a2989b34bd8a5750a)
veracrypt-streebog512 (444ec71554f0a2989b34bd8a5750ae7b5ed8b1cc)
veracrypt-streebog512-boot-xts1024 ($veracrypt$af7a64c7c81f608527552532cc704)
veracrypt-streebog512-boot-xts1024 (af7a64c7c81f608527552532cc7049b0d369e2ce)
veracrypt-streebog512-boot-xts1536 ($veracrypt$0c9d7444e9e64a833e857163787b2)
veracrypt-streebog512-boot-xts1536 (0c9d7444e9e64a833e857163787b2f6349224bdb)
veracrypt-streebog512-boot-xts512 ($veracrypt$2bfe4a72e13388a9ce074bbe0711a)
veracrypt-streebog512-boot-xts512 (2bfe4a72e13388a9ce074bbe0711a48d62f123df)
veracrypt-streebog512-xts1024 ($veracrypt$0f5da0b17c60edcd392058752ec29)
veracrypt-streebog512-xts1024 (0f5da0b17c60edcd392058752ec29c389b140b54)
veracrypt-streebog512-xts1536 ($veracrypt$18d2e8314961850f8fc26d2bc6f89)
veracrypt-streebog512-xts1536 (18d2e8314961850f8fc26d2bc6f896db9c4eee30)
veracrypt-whirlpool ($veracrypt$48f79476aa0aa8327a8a9056e6145)
veracrypt-whirlpool (48f79476aa0aa8327a8a9056e61450f4e2883c9e)
veracrypt-whirlpool-xts1024 ($veracrypt$1b721942019ebe8cedddbed7744a0)
veracrypt-whirlpool-xts1024 (1b721942019ebe8cedddbed7744a0702c0e05328)
veracrypt-whirlpool-xts1536 ($veracrypt$5eb128daef63eff7e6db6aa10a885)
veracrypt-whirlpool-xts1536 (5eb128daef63eff7e6db6aa10a8858f89964f478)
wpa-hccapx-pmk (4843505804000000000235380000000000000000)
wpa-pmk (WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*)
xxhash32 (32d153ff)
xxhash64 (44bc2cf5ad770999)
```

That is 194 lines above, matching the test's own header count exactly
(`recognition_test.go`'s `missing` slice is not deduplicated by type — unlike
`TestRecognitionAccuracy`'s `missed` map — so a handful of types with more
than one missed vector, e.g. `truecrypt-ripemd160-boot-xts1024` and
`truecrypt-whirlpool`, legitimately appear on two lines above, each for a
different vector of that type).

## John-label and Hashcat-mode coverage (measured in Task 12; quoted, not re-derived)

- John-label coverage: **65 of 457 formats**
- Hashcat-mode coverage: **395 of 457 formats**

## What was fixed

1. **`mssql2012` (the pre-diagnosed defect).** `reMSSQLNew` is
   `(?i)^0x0100[0-9a-fA-F]{48}$` — its literal digits `0x0100` can never
   match a `0x0200`-prefixed string, so the cascade's nested "is this actually
   the 0x0200/SQL-Server-2012 form" check was unreachable dead code inherited
   verbatim from the legacy cascade. Added a genuinely separate, correctly
   anchored `reMSSQL2012` (`(?i)^0x0200[0-9a-fA-F]{136}$`, matching the
   vector's real shape: `0x0200` + 136 hex chars = 142 chars total) as its own
   `TierSignature` prototype in `cmd/hashsmith/prototypes_records.go`, ahead
   of the `mssql2005` entry (mirroring the legacy nested-check order). Fixed
   `identify.go`'s regexp table (`reMSSQL2012`) and `prototypes_test.go`'s
   `TestTableCoverageBatchH` (added a coverage case, updated its explanatory
   comments, which previously argued mssql2012 was permanently unreachable).
   `testdata/detect_golden.txt` line 207 went from an empty candidate list to
   `mssql2012` — a pure detection gain (`git diff` shown below).

2. **`cisco4`.** The prototype in `prototypes_records.go` required
   `strings.HasPrefix(in.Normalized, "$4$") &&
   isCiscoType4(in.Normalized)`, but `crack_cisco.go`'s own doc comment and
   `isCiscoType4`'s implementation (which merely *tolerates* an optional
   `$4$` prefix by trimming it, rather than requiring one) agree that the
   canonical Cisco `enable secret 4 <hash>` value is the **bare** 43-char
   crypt-64 body with no tag at all — the format this task's own self-test
   vector uses. ANDing a prefix marker the real format doesn't carry made the
   branch unable to match the shape it exists for. Dropped the AND; the
   Match is now `isCiscoType4(in.Normalized)` alone. Since the remaining
   evidence is exactly "fixed length + crypt-64 alphabet, nothing more" — the
   same class of evidence `looksLikeDescrypt` earns `TierShape` for elsewhere
   in this same file — the prototype's `Tier` was honestly downgraded from
   `TierSignature` to `TierShape` rather than left overclaiming. This fixes
   crackability (golden line for the vector's target: empty → `cisco4`) but,
   correctly, does not move `cisco4` into the certain/likely bucket (see the
   note under "Formats not recognized" above).

3. **`ripemd320`.** `cmd/hashsmith/prototypes_shape.go`'s length-bucketed
   `hexShapeProto` table (32/40/56/60/64/96/128-char buckets) simply had no
   80-character (40-byte) bucket, so RIPEMD-320's own self-test vector — a
   bare 80-hex digest with no distinguishing marker — matched nothing at all.
   Added `hexShapeProto(80, "RIPEMD-320", ...)` following the file's
   established pattern (`TierShape`, `Exclusive: false`, low prevalence:
   RIPEMD-320 is a rarely-implemented double-width RIPEMD-160 variant). Golden
   line: empty → `ripemd320`.

`git diff cmd/hashsmith/testdata/detect_golden.txt` (three lines changed,
all empty-to-non-empty; verified line by line before regenerating — no
non-empty value changed to a different non-empty value anywhere in the file):

```diff
-0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1
+0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1	mssql2012
-2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI
+2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI	cisco4
-de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d
+de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d	ripemd320
```

`TestFalsePositives` passed on the very first run (before any fix) and
required no change.

## What was left as known gaps

Everything else on the 209-name confidence list and the 194-name
crackability list above. They fall into a small number of real, named
categories, none of which is a missing-or-mis-tiered table entry (the
category Step 4 authorizes fixing):

- **Inherent hex-shape ambiguity.** The large majority of the misses (the
  `md5-*`, `sha1-*`, `sha256-*`, `sha512-*`, `sha224-*`, `sha384-*`
  "app-specific construction" families, plus bare `md2`/`md4`/`sha0`/`lm`/
  `ripemd128`/`ripemd256`/`crc32`/`crc32c`/`crc64`/`adler32`/`fnv1a32`/
  `fnv1a64`/`murmur3-32`/`murmur64a-*`/`xxhash32`/`xxhash64`/`keccak*`/
  `sha3_*`/`shake*`/`streebog*`/`sm3`/`blake2*`/`whirlpool`/`java-hashcode`/
  `dahua-auth-md5`/`besder-auth-md5`/`half-md5`/`mysql323`/`cisco-pix`/
  `oracle11g`/`oracle12c`/`cisco-ise`) are all indistinguishable from one or
  more sibling formats by shape alone — several genuinely distinct
  algorithms produce identically-shaped output (e.g. 32-hex is MD5, MD4,
  MD2, NTLM *and* LM at once). The existing cascade already reports every
  live candidate; there is no table correction that makes one of several
  equally-shaped candidates "the" answer without fabricating evidence that
  doesn't exist. Real disambiguation would need either an out-of-band signal
  (context the wire format doesn't carry) or genuinely new logic, not a
  prototype fix.
- **`mysql41`, `mssql2000`, `dane-sha256`, `truecrypt`/`veracrypt`
  variant-suffixed types (e.g. `truecrypt-ripemd160`,
  `veracrypt-sha256-xts1024`, ...), `wpa-pmk`, `wpa-hccapx-pmk`,
  `netntlmv1-nt`/`netntlmv2-nt`, `dcc-nt`/`dcc2-nt`.** Same root cause: the
  self-test vector's *own type* is one of several types a single, correctly
  firing prototype legitimately reports together (e.g. the NetNTLM
  colon-record prototype already reports `netntlmv2,netntlmv1` for the exact
  same captured line that also serves as `netntlmv2-nt`'s and
  `netntlmv1-nt`'s vector — whether the target is a password or an NT hash
  is not something the wire capture encodes). `mysql41`'s own vector is a
  bare 40-hex digest with no leading `*`, which is the one marker
  `reMySQL41` keys on — the vector itself omits the format's only
  distinguishing feature. `truecrypt`/`veracrypt` bare and the `-nt`/plain
  suffix families are similarly two different *representations* of the same
  logical format in the vector corpus (a raw/truncated hex blob for the bare
  type vs. the `$truecrypt$`/`$veracrypt$`-tagged form the suffixed variants
  use), not a missing table entry for the tagged form, which already exists
  and works. None of these are fixable without either editing established
  self-test vector data (out of this task's scope) or writing new
  format-specific parsing.
- **`hmac-ripemd320`, `hmac-ripemd320-saltkey`.** Their vectors are an
  80-hex-char digest plus a decimal field after a colon — the RIPEMD-320-
  length analogue of the generic "salted digest" construction table in
  `detectCompatSaltedTypes`, which currently only special-cases 32/40/56/64-
  hex-char digests (per `TestTableCoverageBatchH`'s own cases). Extending
  that shared, heavily-reused table for one more digest length is real new
  logic, not a local prototype fix, and risks touching many already-non-empty
  golden lines its Compute function already serves — left as a gap rather
  than risk a golden regression under time pressure.
- **`tripcode`.** A bare 10-character alphanumeric string with no marker at
  all; recognizing it reliably without collateral false positives would need
  new, carefully-scoped logic, not a table correction.
- **`descrypt`, and by the same design reasoning `cisco4`, `ripemd320`
  (recognized for cracking, listed above).** These sit at `TierShape` by
  design (length + alphabet only is the weakest evidence the engine models,
  per `internal/hashid/confidence.go`'s own comments), which structurally
  cannot reach "certain"/"likely" confidence unless the match is also
  rivalled by another candidate and dominantly prevalent. This is a
  deliberate design ceiling from earlier tasks, not a bug this task's scope
  covers changing.

## Full test suite

`go test ./... -count=1` passed cleanly (no failures) in this session's own
run — the pre-existing `TestBatchFeasibilityETAThroughRunCrack` wall-clock
flake noted in this task's brief did not occur.
