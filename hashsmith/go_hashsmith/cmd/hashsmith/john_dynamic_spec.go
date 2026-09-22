package main

// John's dynamic formats, as John itself describes them.
//
// "dynamic" is John's compiler for the endless small variations on
// md5(salt.password): rather than a format per scheme, one engine evaluates an
// expression over the password, the salt, a second salt and the username, and
// a few hundred of those expressions ship with a number attached. A record
// names its number — $dynamic_9$<digest>$<salt> — so reading one is a matter
// of knowing which expression the number stands for.
//
// This table is that mapping, transcribed from `john --list=subformats` of
// John the Ripper 1.9.0-jumbo. The expressions are John's own words; the
// comments after them are John's own names for the schemes. Nothing here is
// interpreted at build time: crack_john_dynamic.go parses these strings, which
// keeps the transcription checkable against John line by line.
//
// Two entries are not verbatim. John prints dynamic_1551 and dynamic_1552 with
// an unbalanced parenthesis — "md5($s.$u.(md5($u.:mongo:.$p))" — which is a
// typo in the listing, not a different expression; the balanced form is what
// John computes, and is what appears below.
//
// An expression naming a hash Hashsmith does not implement (tiger, panama,
// haval, skein) simply does not resolve, and a record asking for one is left
// alone rather than claimed and failed.

var johnDynamicSpecs = map[int]string{
	0:    `md5($p)`,      // raw-md5
	1:    `md5($p.$s)`,   // joomla
	2:    `md5(md5($p))`, // e107
	3:    `md5(md5(md5($p)))`,
	4:    `md5($s.$p)`, // OSC
	5:    `md5($s.$p.$s)`,
	6:    `md5(md5($p).$s)`,
	8:    `md5(md5($s).$p)`,
	9:    `md5($s.md5($p))`,
	10:   `md5($s.md5($s.$p))`,
	11:   `md5($s.md5($p.$s))`,
	12:   `md5(md5($s).md5($p))`, // IPB
	13:   `md5(md5($p).md5($s))`,
	14:   `md5($s.md5($p).$s)`,
	15:   `md5($u.md5($p).$s)`,
	16:   `md5(md5(md5($p).$s).$s2)`,
	18:   `md5($s.Y.$p.0xF7.$s)`, // Post.Office MD5
	19:   `md5($p)`,              // Cisco PIX
	20:   `md5($p.$s)`,           // Cisco ASA
	22:   `md5(sha1($p))`,
	23:   `sha1(md5($p))`,
	24:   `sha1($p.$s)`,
	25:   `sha1($s.$p)`,
	26:   `sha1($p)`, // raw-sha1
	29:   `md5(utf16($p))`,
	30:   `md4($p)`, // raw-md4
	31:   `md4($s.$p)`,
	32:   `md4($p.$s)`,
	33:   `md4(utf16($p))`,
	34:   `md5(md4($p))`,
	35:   `sha1(uc($u).:.$p)`,          // ManGOS
	36:   `sha1($u.:.$p)`,              // ManGOS2
	37:   `sha1(lc($u).$p)`,            // SMF
	38:   `sha1($s.sha1($s.sha1($p)))`, // Wolt3BB
	39:   `md5($s.pad16($p))`,          // net-md5
	40:   `sha1($s.pad20($p))`,         // net-sha1
	50:   `sha224($p)`,
	51:   `sha224($s.$p)`,
	52:   `sha224($p.$s)`,
	53:   `sha224(sha224($p))`,
	54:   `sha224(sha224_raw($p))`,
	55:   `sha224(sha224($p).$s)`,
	56:   `sha224($s.sha224($p))`,
	57:   `sha224(sha224($s).sha224($p))`,
	58:   `sha224(sha224($p).sha224($p))`,
	60:   `sha256($p)`,
	61:   `sha256($s.$p)`,
	62:   `sha256($p.$s)`,
	63:   `sha256(sha256($p))`,
	64:   `sha256(sha256_raw($p))`,
	65:   `sha256(sha256($p).$s)`,
	66:   `sha256($s.sha256($p))`,
	67:   `sha256(sha256($s).sha256($p))`,
	68:   `sha256(sha256($p).sha256($p))`,
	70:   `sha384($p)`,
	71:   `sha384($s.$p)`,
	72:   `sha384($p.$s)`,
	73:   `sha384(sha384($p))`,
	74:   `sha384(sha384_raw($p))`,
	75:   `sha384(sha384($p).$s)`,
	76:   `sha384($s.sha384($p))`,
	77:   `sha384(sha384($s).sha384($p))`,
	78:   `sha384(sha384($p).sha384($p))`,
	80:   `sha512($p)`,
	81:   `sha512($s.$p)`,
	82:   `sha512($p.$s)`,
	83:   `sha512(sha512($p))`,
	84:   `sha512(sha512_raw($p))`,
	85:   `sha512(sha512($p).$s)`,
	86:   `sha512($s.sha512($p))`,
	90:   `gost($p)`,
	91:   `gost($s.$p)`,
	92:   `gost($p.$s)`,
	93:   `gost(gost($p))`,
	94:   `gost(gost_raw($p))`,
	95:   `gost(gost($p).$s)`,
	96:   `gost($s.gost($p))`,
	97:   `gost(gost($s).gost($p))`,
	98:   `gost(gost($p).gost($p))`,
	100:  `whirlpool($p)`,
	101:  `whirlpool($s.$p)`,
	102:  `whirlpool($p.$s)`,
	103:  `whirlpool(whirlpool($p))`,
	104:  `whirlpool(whirlpool_raw($p))`,
	105:  `whirlpool(whirlpool($p).$s)`,
	106:  `whirlpool($s.whirlpool($p))`,
	107:  `whirlpool(whirlpool($s).whirlpool($p))`,
	108:  `whirlpool(whirlpool($p).whirlpool($p))`,
	110:  `tiger($p)`,
	111:  `tiger($s.$p)`,
	112:  `tiger($p.$s)`,
	113:  `tiger(tiger($p))`,
	114:  `tiger(tiger_raw($p))`,
	115:  `tiger(tiger($p).$s)`,
	116:  `tiger($s.tiger($p))`,
	117:  `tiger(tiger($s).tiger($p))`,
	118:  `tiger(tiger($p).tiger($p))`,
	120:  `ripemd128($p)`,
	121:  `ripemd128($s.$p)`,
	122:  `ripemd128($p.$s)`,
	123:  `ripemd128(ripemd128($p))`,
	124:  `ripemd128(ripemd128_raw($p))`,
	125:  `ripemd128(ripemd128($p).$s)`,
	126:  `ripemd128($s.ripemd128($p))`,
	127:  `ripemd128(ripemd128($s).ripemd128($p))`,
	128:  `ripemd128(ripemd128($p).ripemd128($p))`,
	130:  `ripemd160($p)`,
	131:  `ripemd160($s.$p)`,
	132:  `ripemd160($p.$s)`,
	133:  `ripemd160(ripemd160($p))`,
	134:  `ripemd160(ripemd160_raw($p))`,
	135:  `ripemd160(ripemd160($p).$s)`,
	136:  `ripemd160($s.ripemd160($p))`,
	137:  `ripemd160(ripemd160($s).ripemd160($p))`,
	138:  `ripemd160(ripemd160($p).ripemd160($p))`,
	140:  `ripemd256($p)`,
	141:  `ripemd256($s.$p)`,
	142:  `ripemd256($p.$s)`,
	143:  `ripemd256(ripemd256($p))`,
	144:  `ripemd256(ripemd256_raw($p))`,
	145:  `ripemd256(ripemd256($p).$s)`,
	146:  `ripemd256($s.ripemd256($p))`,
	147:  `ripemd256(ripemd256($s).ripemd256($p))`,
	148:  `ripemd256(ripemd256($p).ripemd256($p))`,
	150:  `ripemd320($p)`,
	151:  `ripemd320($s.$p)`,
	152:  `ripemd320($p.$s)`,
	153:  `ripemd320(ripemd320($p))`,
	154:  `ripemd320(ripemd320_raw($p))`,
	155:  `ripemd320(ripemd320($p).$s)`,
	156:  `ripemd320($s.ripemd320($p))`,
	157:  `ripemd320(ripemd320($s).ripemd320($p))`,
	158:  `ripemd320(ripemd320($p).ripemd320($p))`,
	160:  `haval128_3($p)`,
	161:  `haval128_3($s.$p)`,
	162:  `haval128_3($p.$s)`,
	163:  `haval128_3(haval128_3($p))`,
	164:  `haval128_3(haval128_3_raw($p))`,
	165:  `haval128_3(haval128_3($p).$s)`,
	166:  `haval128_3($s.haval128_3($p))`,
	167:  `haval128_3(haval128_3($s).haval128_3($p))`,
	168:  `haval128_3(haval128_3($p).haval128_3($p))`,
	170:  `haval128_4($p)`,
	171:  `haval128_4($s.$p)`,
	172:  `haval128_4($p.$s)`,
	173:  `haval128_4(haval128_4($p))`,
	174:  `haval128_4(haval128_4_raw($p))`,
	175:  `haval128_4(haval128_4($p).$s)`,
	176:  `haval128_4($s.haval128_4($p))`,
	177:  `haval128_4(haval128_4($s).haval128_4($p))`,
	178:  `haval128_4(haval128_4($p).haval128_4($p))`,
	180:  `haval128_5($p)`,
	181:  `haval128_5($s.$p)`,
	182:  `haval128_5($p.$s)`,
	183:  `haval128_5(haval128_5($p))`,
	184:  `haval128_5(haval128_5_raw($p))`,
	185:  `haval128_5(haval128_5($p).$s)`,
	186:  `haval128_5($s.haval128_5($p))`,
	187:  `haval128_5(haval128_5($s).haval128_5($p))`,
	188:  `haval128_5(haval128_5($p).haval128_5($p))`,
	190:  `haval160_3($p)`,
	191:  `haval160_3($s.$p)`,
	192:  `haval160_3($p.$s)`,
	193:  `haval160_3(haval160_3($p))`,
	194:  `haval160_3(haval160_3_raw($p))`,
	195:  `haval160_3(haval160_3($p).$s)`,
	196:  `haval160_3($s.haval160_3($p))`,
	197:  `haval160_3(haval160_3($s).haval160_3($p))`,
	198:  `haval160_3(haval160_3($p).haval160_3($p))`,
	200:  `haval160_4($p)`,
	201:  `haval160_4($s.$p)`,
	202:  `haval160_4($p.$s)`,
	203:  `haval160_4(haval160_4($p))`,
	204:  `haval160_4(haval160_4_raw($p))`,
	205:  `haval160_4(haval160_4($p).$s)`,
	206:  `haval160_4($s.haval160_4($p))`,
	207:  `haval160_4(haval160_4($s).haval160_4($p))`,
	208:  `haval160_4(haval160_4($p).haval160_4($p))`,
	210:  `haval160_5($p)`,
	211:  `haval160_5($s.$p)`,
	212:  `haval160_5($p.$s)`,
	213:  `haval160_5(haval160_5($p))`,
	214:  `haval160_5(haval160_5_raw($p))`,
	215:  `haval160_5(haval160_5($p).$s)`,
	216:  `haval160_5($s.haval160_5($p))`,
	217:  `haval160_5(haval160_5($s).haval160_5($p))`,
	218:  `haval160_5(haval160_5($p).haval160_5($p))`,
	220:  `haval192_3($p)`,
	221:  `haval192_3($s.$p)`,
	222:  `haval192_3($p.$s)`,
	223:  `haval192_3(haval192_3($p))`,
	224:  `haval192_3(haval192_3_raw($p))`,
	225:  `haval192_3(haval192_3($p).$s)`,
	226:  `haval192_3($s.haval192_3($p))`,
	227:  `haval192_3(haval192_3($s).haval192_3($p))`,
	228:  `haval192_3(haval192_3($p).haval192_3($p))`,
	230:  `haval192_4($p)`,
	231:  `haval192_4($s.$p)`,
	232:  `haval192_4($p.$s)`,
	233:  `haval192_4(haval192_4($p))`,
	234:  `haval192_4(haval192_4_raw($p))`,
	235:  `haval192_4(haval192_4($p).$s)`,
	236:  `haval192_4($s.haval192_4($p))`,
	237:  `haval192_4(haval192_4($s).haval192_4($p))`,
	238:  `haval192_4(haval192_4($p).haval192_4($p))`,
	240:  `haval192_5($p)`,
	241:  `haval192_5($s.$p)`,
	242:  `haval192_5($p.$s)`,
	243:  `haval192_5(haval192_5($p))`,
	244:  `haval192_5(haval192_5_raw($p))`,
	245:  `haval192_5(haval192_5($p).$s)`,
	246:  `haval192_5($s.haval192_5($p))`,
	247:  `haval192_5(haval192_5($s).haval192_5($p))`,
	248:  `haval192_5(haval192_5($p).haval192_5($p))`,
	250:  `haval224_3($p)`,
	251:  `haval224_3($s.$p)`,
	252:  `haval224_3($p.$s)`,
	253:  `haval224_3(haval224_3($p))`,
	254:  `haval224_3(haval224_3_raw($p))`,
	255:  `haval224_3(haval224_3($p).$s)`,
	256:  `haval224_3($s.haval224_3($p))`,
	257:  `haval224_3(haval224_3($s).haval224_3($p))`,
	258:  `haval224_3(haval224_3($p).haval224_3($p))`,
	260:  `haval224_4($p)`,
	261:  `haval224_4($s.$p)`,
	262:  `haval224_4($p.$s)`,
	263:  `haval224_4(haval224_4($p))`,
	264:  `haval224_4(haval224_4_raw($p))`,
	265:  `haval224_4(haval224_4($p).$s)`,
	266:  `haval224_4($s.haval224_4($p))`,
	267:  `haval224_4(haval224_4($s).haval224_4($p))`,
	268:  `haval224_4(haval224_4($p).haval224_4($p))`,
	270:  `haval224_5($p)`,
	271:  `haval224_5($s.$p)`,
	272:  `haval224_5($p.$s)`,
	273:  `haval224_5(haval224_5($p))`,
	274:  `haval224_5(haval224_5_raw($p))`,
	275:  `haval224_5(haval224_5($p).$s)`,
	276:  `haval224_5($s.haval224_5($p))`,
	277:  `haval224_5(haval224_5($s).haval224_5($p))`,
	278:  `haval224_5(haval224_5($p).haval224_5($p))`,
	280:  `haval256_3($p)`,
	281:  `haval256_3($s.$p)`,
	282:  `haval256_3($p.$s)`,
	283:  `haval256_3(haval256_3($p))`,
	284:  `haval256_3(haval256_3_raw($p))`,
	285:  `haval256_3(haval256_3($p).$s)`,
	286:  `haval256_3($s.haval256_3($p))`,
	287:  `haval256_3(haval256_3($s).haval256_3($p))`,
	288:  `haval256_3(haval256_3($p).haval256_3($p))`,
	290:  `haval256_4($p)`,
	291:  `haval256_4($s.$p)`,
	292:  `haval256_4($p.$s)`,
	293:  `haval256_4(haval256_4($p))`,
	294:  `haval256_4(haval256_4_raw($p))`,
	295:  `haval256_4(haval256_4($p).$s)`,
	296:  `haval256_4($s.haval256_4($p))`,
	297:  `haval256_4(haval256_4($s).haval256_4($p))`,
	298:  `haval256_4(haval256_4($p).haval256_4($p))`,
	300:  `haval256_5($p)`,
	301:  `haval256_5($s.$p)`,
	302:  `haval256_5($p.$s)`,
	303:  `haval256_5(haval256_5($p))`,
	304:  `haval256_5(haval256_5_raw($p))`,
	305:  `haval256_5(haval256_5($p).$s)`,
	306:  `haval256_5($s.haval256_5($p))`,
	307:  `haval256_5(haval256_5($s).haval256_5($p))`,
	308:  `haval256_5(haval256_5($p).haval256_5($p))`,
	310:  `md2($p)`,
	311:  `md2($s.$p)`,
	312:  `md2($p.$s)`,
	313:  `md2(md2($p))`,
	314:  `md2(md2_raw($p))`,
	315:  `md2(md2($p).$s)`,
	316:  `md2($s.md2($p))`,
	317:  `md2(md2($s).md2($p))`,
	318:  `md2(md2($p).md2($p))`,
	320:  `panama($p)`,
	321:  `panama($s.$p)`,
	322:  `panama($p.$s)`,
	323:  `panama(panama($p))`,
	324:  `panama(panama_raw($p))`,
	325:  `panama(panama($p).$s)`,
	326:  `panama($s.panama($p))`,
	327:  `panama(panama($s).panama($p))`,
	328:  `panama(panama($p).panama($p))`,
	330:  `skein224($p)`,
	331:  `skein224($s.$p)`,
	332:  `skein224($p.$s)`,
	333:  `skein224(skein224($p))`,
	334:  `skein224(skein224_raw($p))`,
	335:  `skein224(skein224($p).$s)`,
	336:  `skein224($s.skein224($p))`,
	337:  `skein224(skein224($s).skein224($p))`,
	338:  `skein224(skein224($p).skein224($p))`,
	340:  `skein256($p)`,
	341:  `skein256($s.$p)`,
	342:  `skein256($p.$s)`,
	343:  `skein256(skein256($p))`,
	344:  `skein256(skein256_raw($p))`,
	345:  `skein256(skein256($p).$s)`,
	346:  `skein256($s.skein256($p))`,
	347:  `skein256(skein256($s).skein256($p))`,
	348:  `skein256(skein256($p).skein256($p))`,
	350:  `skein384($p)`,
	351:  `skein384($s.$p)`,
	352:  `skein384($p.$s)`,
	353:  `skein384(skein384($p))`,
	354:  `skein384(skein384_raw($p))`,
	355:  `skein384(skein384($p).$s)`,
	356:  `skein384($s.skein384($p))`,
	357:  `skein384(skein384($s).skein384($p))`,
	358:  `skein384(skein384($p).skein384($p))`,
	360:  `skein512($p)`,
	361:  `skein512($s.$p)`,
	362:  `skein512($p.$s)`,
	363:  `skein512(skein512($p))`,
	364:  `skein512(skein512_raw($p))`,
	365:  `skein512(skein512($p).$s)`,
	366:  `skein512($s.skein512($p))`,
	367:  `skein512(skein512($s).skein512($p))`,
	368:  `skein512(skein512($p).skein512($p))`,
	370:  `sha3_224($p)`,
	371:  `sha3_224($s.$p)`,
	372:  `sha3_224($p.$s)`,
	373:  `sha3_224(sha3_224($p))`,
	374:  `sha3_224(sha3_224_raw($p))`,
	375:  `sha3_224(sha3_224($p).$s)`,
	376:  `sha3_224($s.sha3_224($p))`,
	377:  `sha3_224(sha3_224($s).sha3_224($p))`,
	378:  `sha3_224(sha3_224($p).sha3_224($p))`,
	380:  `sha3_256($p)`,
	381:  `sha3_256($s.$p)`,
	382:  `sha3_256($p.$s)`,
	383:  `sha3_256(sha3_256($p))`,
	384:  `sha3_256(sha3_256_raw($p))`,
	385:  `sha3_256(sha3_256($p).$s)`,
	386:  `sha3_256($s.sha3_256($p))`,
	387:  `sha3_256(sha3_256($s).sha3_256($p))`,
	388:  `sha3_256(sha3_256($p).sha3_256($p))`,
	390:  `sha3_384($p)`,
	391:  `sha3_384($s.$p)`,
	392:  `sha3_384($p.$s)`,
	393:  `sha3_384(sha3_384($p))`,
	394:  `sha3_384(sha3_384_raw($p))`,
	395:  `sha3_384(sha3_384($p).$s)`,
	396:  `sha3_384($s.sha3_384($p))`,
	397:  `sha3_384(sha3_384($s).sha3_384($p))`,
	398:  `sha3_384(sha3_384($p).sha3_384($p))`,
	400:  `sha3_512($p)`,
	401:  `sha3_512($s.$p)`,
	402:  `sha3_512($p.$s)`,
	403:  `sha3_512(sha3_512($p))`,
	404:  `sha3_512(sha3_512_raw($p))`,
	405:  `sha3_512(sha3_512($p).$s)`,
	406:  `sha3_512($s.sha3_512($p))`,
	407:  `sha3_512(sha3_512($s).sha3_512($p))`,
	408:  `sha3_512(sha3_512($p).sha3_512($p))`,
	410:  `keccak_256($p)`,
	411:  `keccak_256($s.$p)`,
	412:  `keccak_256($p.$s)`,
	413:  `keccak_256(keccak_256($p))`,
	414:  `keccak_256(keccak_256_raw($p))`,
	415:  `keccak_256(keccak_256($p).$s)`,
	416:  `keccak_256($s.keccak_256($p))`,
	417:  `keccak_256(keccak_256($s).keccak_256($p))`,
	418:  `keccak_256(keccak_256($p).keccak_256($p))`,
	420:  `keccak_512($p)`,
	421:  `keccak_512($s.$p)`,
	422:  `keccak_512($p.$s)`,
	423:  `keccak_512(keccak_512($p))`,
	424:  `keccak_512(keccak_512_raw($p))`,
	425:  `keccak_512(keccak_512($p).$s)`,
	426:  `keccak_512($s.keccak_512($p))`,
	427:  `keccak_512(keccak_512($s).keccak_512($p))`,
	428:  `keccak_512(keccak_512($p).keccak_512($p))`,
	1001: `md5(md5(md5(md5($p))))`,
	1002: `md5(md5(md5(md5(md5($p)))))`,
	1003: `md5(md5($p).md5($p))`,
	1004: `md5(md5(md5(md5(md5(md5($p))))))`,
	1005: `md5(md5(md5(md5(md5(md5(md5($p)))))))`,
	1006: `md5(md5(md5(md5(md5(md5(md5(md5($p))))))))`,
	1007: `md5(md5($p).$s)`,                // vBulletin
	1008: `md5($p.$s)`,                     // RADIUS User-Password
	1009: `md5($s.$p)`,                     // RADIUS Responses
	1010: `md5($p null_padded_to_len_100)`, // RAdmin v2.x MD5
	1011: `md5($p.md5($s))`,                // webEdition CMS
	1012: `md5($p.md5($s))`,                // webEdition CMS
	// John prints dynamic_1013 as md5($p.PMD5(username)), but its records do
	// not carry a username: the salt field already holds that inner digest,
	// precomputed. What the record implies is therefore md5($p.$s), which is
	// what the vector confirms.
	1013: `md5($p.$s)`,         // webEdition CMS
	1014: `md5($p.$s)`,         // long salt
	1015: `md5(md5($p.$u).$s)`, // PostgreSQL 'pass the hash'
	1016: `md5($p.$s)`,         // long salt
	1017: `md5($s.$p)`,         // long salt
	1018: `md5(sha1(sha1($p)))`,
	1019: `md5(sha1(sha1(md5($p))))`,
	1020: `md5(sha1(md5($p)))`,
	1021: `md5(sha1(md5(sha1($p))))`,
	1022: `md5(sha1(md5(sha1(md5($p)))))`,
	1023: `sha1($p)`,             // hash truncated to length 32
	1024: `sha1(md5($p))`,        // hash truncated to length 32
	1025: `sha1(md5(md5($p)))`,   // hash truncated to length 32
	1026: `sha1(sha1($p))`,       // hash truncated to length 32
	1027: `sha1(sha1(sha1($p)))`, // hash truncated to length 32
	1028: `sha1(sha1_raw($p))`,   // hash truncated to length 32
	1029: `sha256($p)`,           // hash truncated to length 32
	1030: `whirlpool($p)`,        // hash truncated to length 32
	1031: `gost($p)`,             // hash truncated to length 32
	1032: `sha1_64(utf16($p))`,   // PeopleSoft
	1033: `sha1_64(utf16($p).$s)`,
	1034: `md5($p.$u)`, // PostgreSQL MD5
	1300: `md5(md5_raw($p))`,
	1350: `md5(md5($s.$p):$s)`,
	1400: `sha1(utf16($p))`,       // Microsoft CREDHIST
	1401: `md5($u.\nskyper\n.$p)`, // Skype MD5
	1501: `sha1($s.sha1($p))`,     // Redmine
	1502: `sha1(sha1($p).$s)`,     // XenForo SHA-1
	1503: `sha256(sha256($p).$s)`, // XenForo SHA-256
	1504: `sha1($s.$p.$s)`,
	1505: `md5($p.$s.md5($p.$s))`,
	1506: `md5($u.:XDB:.$p)`,       // Oracle 12c "H" hash
	1507: `sha1(utf16($const.$p))`, // Mcafee master pass
	1518: `md5(sha1($p).md5($p).sha1($p))`,
	1528: `sha256($s.$p.$s)`,               // Telegram for Android
	1529: `sha1($p null_padded_to_len_32)`, // DeepSound
	1550: `md5($u.:mongo:.$p)`,             // MONGODB-CR system hash
	1551: `md5($s.$u.md5($u.:mongo:.$p))`,
	1552: `md5($s.$u.md5($u.:mongo:.$p))`,
	1560: `md5($s.$p.$s2)`, // SocialEngine
	// John prints dynamic_1588 as sha256($s.sha1($p)), leaving out that
	// ColdFusion writes the inner digest in upper case.
	1588: `sha256($s.uc(sha1($p)))`, // ColdFusion 11
	// John prints dynamic_1590 as sha1(utf16be(space_pad_10(uc($s)).$p)),
	// which describes an AS/400 record whose salt is plain text. The records
	// store it already upper-cased, blank-padded and in UTF-16BE, so what is
	// left to convert is the password.
	1590: `sha1($s.utf16be($p))`,               // IBM AS/400 SHA1
	1592: `sha1($s.sha1($s.sha1($p)))`,         // wbb3
	1600: `sha1($s.utf16le($p))`,               // Oracle PeopleSoft PS_TOKEN
	1602: `sha256(#.$salt.-.$pass)`,            // QAS vas_auth
	1608: `sha256(sha256_raw(sha256_raw($p)))`, // Neo Wallet
	2000: `md5($p)`,                            // PW > 55 bytes
	2001: `md5($p.$s)`,                         // joomla) (PW > 23 bytes
	2002: `md5(md5($p))`,                       // e107) (PW > 55 bytes
	2003: `md5(md5(md5($p)))`,                  // PW > 55 bytes
	2004: `md5($s.$p)`,                         // OSC) (PW > 31 bytes
	2005: `md5($s.$p.$s)`,                      // PW > 31 bytes
	2006: `md5(md5($p).$s)`,                    // PW > 55 bytes
	2008: `md5(md5($s).$p)`,                    // PW > 23 bytes
	2009: `md5($s.md5($p))`,                    // salt > 23 bytes
	2010: `md5($s.md5($s.$p))`,                 // PW > 32 or salt > 23 bytes
	2011: `md5($s.md5($p.$s))`,                 // PW > 32 or salt > 23 bytes
	2014: `md5($s.md5($p).$s)`,                 // PW > 55 or salt > 11 bytes
}
