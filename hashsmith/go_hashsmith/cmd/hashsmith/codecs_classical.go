package main

// The classical ciphers the catalogue was missing.
//
// Every one of these follows the convention the existing ciphers set: LETTERS
// are transformed and everything else passes through untouched, case is
// preserved, and the key advances only on a letter. That matters more than it
// looks: a cipher that consumed key material on spaces would produce a
// different answer for the same message written with different punctuation,
// and every published example of these ciphers is written without any.

import (
	"errors"
	"fmt"
	"strings"
)

// ── shared helpers ────────────────────────────────────────────────────────────

// isLetterRune reports whether r is an ASCII letter. The byte-taking
// isASCIILetter in rules_john_dialect.go answers the same question for John's
// rule engine; these ciphers walk runes, because a message may hold anything
// and only the letters are enciphered.
func isLetterRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// letterIndex is a letter's position in the alphabet, 0 to 25.
func letterIndex(r rune) int {
	if r >= 'a' && r <= 'z' {
		return int(r - 'a')
	}
	return int(r - 'A')
}

// letterFrom rebuilds a letter at index i with the case of the original.
func letterFrom(i int, like rune) rune {
	i = ((i % 26) + 26) % 26
	if like >= 'a' && like <= 'z' {
		return rune('a' + i)
	}
	return rune('A' + i)
}

// alphabeticKey checks a key is letters and returns it folded to lower case.
func alphabeticKey(key, cipher string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%s needs a key: pass it with -k", cipher)
	}
	for _, r := range key {
		if !isLetterRune(r) {
			return "", fmt.Errorf("a %s key is letters only, and this one holds %q", cipher, string(r))
		}
	}
	return strings.ToLower(key), nil
}

// substituteLetters walks text applying shift to each letter, where shift is
// given the letter's index and its position among the letters seen so far.
func substituteLetters(text string, shift func(value, position int) int) string {
	out := make([]rune, 0, len(text))
	position := 0
	for _, r := range text {
		if !isLetterRune(r) {
			out = append(out, r)
			continue
		}
		out = append(out, letterFrom(shift(letterIndex(r), position), r))
		position++
	}
	return string(out)
}

// ── Affine ────────────────────────────────────────────────────────────────────

// affineKey reads the "a,b" pair and checks that a is invertible.
//
// Only twelve values of a work: the multiplier has to be coprime with 26, or
// two different letters encipher to the same one and the message cannot be
// read back even with the key. That is the whole reason this cipher has a
// key-validity rule at all, and it is checked rather than assumed.
func affineKey(key string) (a, b int, err error) {
	parts := strings.Split(strings.ReplaceAll(key, " ", ""), ",")
	if len(parts) != 2 {
		return 0, 0, errors.New("an affine key is two numbers, the multiplier and the shift: -k 5,8")
	}
	if _, err := fmt.Sscanf(parts[0], "%d", &a); err != nil {
		return 0, 0, errors.New("the affine multiplier is not a number")
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &b); err != nil {
		return 0, 0, errors.New("the affine shift is not a number")
	}
	a = ((a % 26) + 26) % 26
	b = ((b % 26) + 26) % 26
	if gcd(a, 26) != 1 {
		return 0, 0, fmt.Errorf("an affine multiplier must be coprime with 26, and %d is not: two letters would encipher to the same one and the message could not be read back", a)
	}
	return a, b, nil
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// modInverse26 returns the multiplicative inverse of a modulo 26. There are
// only twelve to find, so the search is the clearest way to write it.
func modInverse26(a int) int {
	for i := 1; i < 26; i++ {
		if a*i%26 == 1 {
			return i
		}
	}
	return 0
}

func encodeAffine(text, key string) (string, error) {
	a, b, err := affineKey(key)
	if err != nil {
		return "", err
	}
	return substituteLetters(text, func(v, _ int) int { return a*v + b }), nil
}

func decodeAffine(text, key string) (string, error) {
	a, b, err := affineKey(key)
	if err != nil {
		return "", err
	}
	inv := modInverse26(a)
	return substituteLetters(text, func(v, _ int) int { return inv * (v - b) }), nil
}

// ── Beaufort ──────────────────────────────────────────────────────────────────

// Beaufort is Vigenere's subtraction: C = K - P rather than P + K. That one
// change makes it SELF-RECIPROCAL — enciphering twice returns the original —
// which is why both directions below call the same function, and why a
// Beaufort machine needed no decrypt setting.
func beaufortApply(text, key string) (string, error) {
	k, err := alphabeticKey(key, "Beaufort")
	if err != nil {
		return "", err
	}
	return substituteLetters(text, func(v, pos int) int {
		return int(k[pos%len(k)]-'a') - v
	}), nil
}

// ── Autokey ───────────────────────────────────────────────────────────────────

// Autokey is Vigenere with the PLAINTEXT appended to the key, so the key never
// repeats. Vigenere's weakness is that a repeating key leaves a period to
// find; this removes it, which is why Vigenere fell in the 1860s and this did
// not fall until much later.
//
// The consequence is that decoding cannot be done key-first: each recovered
// letter becomes key material for the next, so the two directions are
// genuinely different code rather than one with the sign flipped.
func encodeAutokey(text, key string) (string, error) {
	k, err := alphabeticKey(key, "Autokey")
	if err != nil {
		return "", err
	}
	stream := []int{}
	for _, r := range k {
		stream = append(stream, int(r-'a'))
	}
	out := make([]rune, 0, len(text))
	position := 0
	for _, r := range text {
		if !isLetterRune(r) {
			out = append(out, r)
			continue
		}
		v := letterIndex(r)
		out = append(out, letterFrom(v+stream[position], r))
		stream = append(stream, v) // the plaintext becomes the key
		position++
	}
	return string(out), nil
}

func decodeAutokey(text, key string) (string, error) {
	k, err := alphabeticKey(key, "Autokey")
	if err != nil {
		return "", err
	}
	stream := []int{}
	for _, r := range k {
		stream = append(stream, int(r-'a'))
	}
	out := make([]rune, 0, len(text))
	position := 0
	for _, r := range text {
		if !isLetterRune(r) {
			out = append(out, r)
			continue
		}
		v := ((letterIndex(r)-stream[position])%26 + 26) % 26
		out = append(out, letterFrom(v, r))
		stream = append(stream, v) // ... and it is recovered as we go
		position++
	}
	return string(out), nil
}

// ── Gronsfeld ─────────────────────────────────────────────────────────────────

// Gronsfeld is Vigenere with a NUMERIC key, which is its entire point: a
// courier could memorise a number and no key table was needed. The cost is
// that each position shifts by at most nine rather than twenty-five.
func gronsfeldKey(key string) ([]int, error) {
	if key == "" {
		return nil, errors.New("Gronsfeld needs a numeric key: pass it with -k, for example -k 31415")
	}
	shifts := make([]int, 0, len(key))
	for _, r := range key {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("a Gronsfeld key is digits only, and this one holds %q", string(r))
		}
		shifts = append(shifts, int(r-'0'))
	}
	return shifts, nil
}

func encodeGronsfeld(text, key string) (string, error) {
	shifts, err := gronsfeldKey(key)
	if err != nil {
		return "", err
	}
	return substituteLetters(text, func(v, pos int) int { return v + shifts[pos%len(shifts)] }), nil
}

func decodeGronsfeld(text, key string) (string, error) {
	shifts, err := gronsfeldKey(key)
	if err != nil {
		return "", err
	}
	return substituteLetters(text, func(v, pos int) int { return v - shifts[pos%len(shifts)] }), nil
}

// ── Playfair ──────────────────────────────────────────────────────────────────

// Playfair enciphers PAIRS of letters against a five-by-five square, which is
// what made it the first practical digraph cipher and why frequency analysis
// of single letters gets nowhere against it.
//
// Three things about it are lossy and all three are consequences of fitting
// twenty-six letters into twenty-five cells and needing even-length pairs:
// J becomes I, a doubled letter inside a pair is separated by an X, and an odd
// message gains a trailing X. A decoded message therefore does not always
// equal the original, which is a property of the cipher rather than of this
// implementation — the padding is left in place rather than guessed away.
const playfairFiller = 'x'

// playfairSquare builds the key square.
//
// Only the LETTERS of the key are used and everything else is ignored, because
// a Playfair key is a phrase and every published example is written as one —
// "playfair example" has a space in it. Rejecting the space would reject the
// cipher's own textbook case.
func playfairSquare(key string) ([25]byte, map[byte]int, error) {
	var letters strings.Builder
	for _, r := range strings.ToLower(key) {
		if isLetterRune(r) {
			letters.WriteRune(r)
		}
	}
	k := letters.String()
	if k == "" {
		return [25]byte{}, nil, errors.New("Playfair needs a key phrase: pass it with -k")
	}
	var square [25]byte
	at := 0
	seen := make(map[byte]bool, 25)
	place := func(c byte) {
		if c == 'j' {
			c = 'i'
		}
		if seen[c] || at >= 25 {
			return
		}
		seen[c] = true
		square[at] = c
		at++
	}
	for i := 0; i < len(k); i++ {
		place(k[i])
	}
	for c := byte('a'); c <= 'z'; c++ {
		place(c)
	}
	index := make(map[byte]int, 25)
	for i, c := range square {
		index[c] = i
	}
	return square, index, nil
}

// playfairPairs splits the letters of text into digraphs, inserting the filler
// where a pair would repeat and at the end when the count is odd.
func playfairPairs(text string) [][2]byte {
	letters := make([]byte, 0, len(text))
	for _, r := range strings.ToLower(text) {
		if isLetterRune(r) {
			if r == 'j' {
				r = 'i'
			}
			letters = append(letters, byte(r))
		}
	}
	var pairs [][2]byte
	for i := 0; i < len(letters); {
		a := letters[i]
		var b byte
		switch {
		case i+1 >= len(letters):
			b = playfairFiller
			i++
		case letters[i+1] == a:
			b = playfairFiller
			i++
		default:
			b = letters[i+1]
			i += 2
		}
		if a == b && a == playfairFiller {
			// Two fillers in a row would loop; step past instead.
			continue
		}
		pairs = append(pairs, [2]byte{a, b})
	}
	return pairs
}

func playfairApply(text, key string, direction int) (string, error) {
	square, index, err := playfairSquare(key)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, pair := range playfairPairs(text) {
		ai, bi := index[pair[0]], index[pair[1]]
		ar, ac := ai/5, ai%5
		br, bc := bi/5, bi%5
		switch {
		case ar == br: // same row: move along it
			ac = (ac + direction + 5) % 5
			bc = (bc + direction + 5) % 5
		case ac == bc: // same column: move down it
			ar = (ar + direction + 5) % 5
			br = (br + direction + 5) % 5
		default: // a rectangle: swap the columns
			ac, bc = bc, ac
		}
		out.WriteByte(square[ar*5+ac])
		out.WriteByte(square[br*5+bc])
	}
	return out.String(), nil
}

func encodePlayfair(text, key string) (string, error) { return playfairApply(text, key, +1) }
func decodePlayfair(text, key string) (string, error) { return playfairApply(text, key, -1) }

// ── Polybius squares ──────────────────────────────────────────────────────────

// polybiusSquare builds an n-by-n square from a key phrase followed by the
// rest of the alphabet.
//
// At five by five the alphabet does not fit and J is folded into I, the same
// compromise Playfair makes. At six by six it does fit, with the ten digits
// filling the remaining cells — which is what ADFGVX was for: a field cipher
// that could carry map references and unit numbers without spelling them out.
func polybiusSquare(key string, n int) ([]byte, map[byte][2]int, error) {
	var pool []byte
	seen := make(map[byte]bool, n*n)
	place := func(c byte) {
		if n == 5 && c == 'j' {
			c = 'i'
		}
		if seen[c] || len(pool) >= n*n {
			return
		}
		seen[c] = true
		pool = append(pool, c)
	}
	for _, r := range strings.ToLower(key) {
		if isLetterRune(r) || (n == 6 && r >= '0' && r <= '9') {
			place(byte(r))
		}
	}
	for c := byte('a'); c <= 'z'; c++ {
		place(c)
	}
	if n == 6 {
		for c := byte('0'); c <= '9'; c++ {
			place(c)
		}
	}
	if len(pool) != n*n {
		return nil, nil, fmt.Errorf("a %d-by-%d square needs %d cells and this key filled %d", n, n, n*n, len(pool))
	}
	index := make(map[byte][2]int, n*n)
	for i, c := range pool {
		index[c] = [2]int{i / n, i % n}
	}
	return pool, index, nil
}

// polybiusLetters reduces text to the characters a square can hold.
func polybiusLetters(text string, n int) []byte {
	out := make([]byte, 0, len(text))
	for _, r := range strings.ToLower(text) {
		switch {
		case isLetterRune(r):
			if n == 5 && r == 'j' {
				r = 'i'
			}
			out = append(out, byte(r))
		case n == 6 && r >= '0' && r <= '9':
			out = append(out, byte(r))
		}
	}
	return out
}

// ── Bifid ─────────────────────────────────────────────────────────────────────

// Bifid writes each letter's row and column, then reads the rows and the
// columns as one sequence and re-pairs them. That is FRACTIONATION: a letter's
// two halves end up in different pairs, so one plaintext letter influences two
// ciphertext letters and back again.
//
// Delastelle's point in 1901 was that this defeats the frequency analysis that
// breaks a simple substitution, using nothing but a pencil.
func encodeBifid(text, key string) (string, error) {
	square, index, err := polybiusSquare(key, 5)
	if err != nil {
		return "", err
	}
	letters := polybiusLetters(text, 5)
	rows := make([]int, 0, len(letters))
	cols := make([]int, 0, len(letters))
	for _, c := range letters {
		rc := index[c]
		rows = append(rows, rc[0])
		cols = append(cols, rc[1])
	}
	stream := append(rows, cols...)
	var out strings.Builder
	for i := 0; i+1 < len(stream); i += 2 {
		out.WriteByte(square[stream[i]*5+stream[i+1]])
	}
	return out.String(), nil
}

func decodeBifid(text, key string) (string, error) {
	square, index, err := polybiusSquare(key, 5)
	if err != nil {
		return "", err
	}
	letters := polybiusLetters(text, 5)
	stream := make([]int, 0, len(letters)*2)
	for _, c := range letters {
		rc := index[c]
		stream = append(stream, rc[0], rc[1])
	}
	half := len(stream) / 2
	var out strings.Builder
	for i := 0; i < half; i++ {
		out.WriteByte(square[stream[i]*5+stream[half+i]])
	}
	return out.String(), nil
}

// ── Nihilist ──────────────────────────────────────────────────────────────────

// The Nihilist cipher adds two Polybius coordinates together as two-digit
// numbers, so the ciphertext is a list of numbers rather than letters. It was
// used by Russian revolutionaries in the 1880s, and its weakness is visible in
// the output: a sum of two numbers each between 11 and 55 lies between 22 and
// 110, and the distribution of those sums leaks the key's length.
func nihilistKey(key string) (string, string, error) {
	parts := strings.SplitN(key, ",", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("a Nihilist key is the square's key phrase and the additive key, separated by a comma: -k zebras,russian")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func encodeNihilist(text, key string) (string, error) {
	squareKey, addKey, err := nihilistKey(key)
	if err != nil {
		return "", err
	}
	_, index, err := polybiusSquare(squareKey, 5)
	if err != nil {
		return "", err
	}
	value := func(c byte) int {
		rc := index[c]
		return (rc[0]+1)*10 + rc[1] + 1
	}
	adds := polybiusLetters(addKey, 5)
	if len(adds) == 0 {
		return "", errors.New("the Nihilist additive key holds no letters")
	}
	letters := polybiusLetters(text, 5)
	out := make([]string, 0, len(letters))
	for i, c := range letters {
		out = append(out, fmt.Sprint(value(c)+value(adds[i%len(adds)])))
	}
	return strings.Join(out, " "), nil
}

func decodeNihilist(text, key string) (string, error) {
	squareKey, addKey, err := nihilistKey(key)
	if err != nil {
		return "", err
	}
	square, index, err := polybiusSquare(squareKey, 5)
	if err != nil {
		return "", err
	}
	value := func(c byte) int {
		rc := index[c]
		return (rc[0]+1)*10 + rc[1] + 1
	}
	adds := polybiusLetters(addKey, 5)
	if len(adds) == 0 {
		return "", errors.New("the Nihilist additive key holds no letters")
	}
	var out strings.Builder
	for i, field := range strings.Fields(text) {
		var n int
		if _, err := fmt.Sscanf(field, "%d", &n); err != nil {
			return "", fmt.Errorf("%q is not one of the numbers this cipher produces", field)
		}
		v := n - value(adds[i%len(adds)])
		row, col := v/10-1, v%10-1
		if row < 0 || row > 4 || col < 0 || col > 4 {
			return "", fmt.Errorf("%q does not subtract to a square coordinate; the additive key is probably wrong", field)
		}
		out.WriteByte(square[row*5+col])
	}
	return out.String(), nil
}

// ── Columnar transposition ────────────────────────────────────────────────────

// transpositionLetters reduces text to the characters a transposition moves.
//
// Unlike a square's alphabet this keeps the case it was given: a transposition
// permutes the characters it is handed and does not substitute anything, so
// there is no reason for it to destroy case the way a five-by-five square must.
func transpositionLetters(text string) []byte {
	out := make([]byte, 0, len(text))
	for _, r := range text {
		if isLetterRune(r) || (r >= '0' && r <= '9') {
			out = append(out, byte(r))
		}
	}
	return out
}

// columnarOrder returns the order the columns are read in: the key's letters
// sorted alphabetically, ties broken by which came first.
func columnarOrder(key string) ([]int, error) {
	var letters []byte
	for _, r := range strings.ToLower(key) {
		if isLetterRune(r) || (r >= '0' && r <= '9') {
			letters = append(letters, byte(r))
		}
	}
	if len(letters) < 2 {
		return nil, errors.New("a columnar key needs at least two characters: -k zebras")
	}
	order := make([]int, len(letters))
	for i := range order {
		order[i] = i
	}
	// A stable insertion sort, so equal letters keep their left-to-right
	// order — which is the rule every published example uses.
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && letters[order[j]] < letters[order[j-1]]; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	return order, nil
}

// Columnar transposition writes the message in rows under the key and reads it
// out in columns, taking the columns in the key's alphabetical order. Nothing
// is substituted — the letters are the same letters — which is why it was used
// on TOP of a substitution rather than instead of one.
func encodeColumnar(text, key string) (string, error) {
	order, err := columnarOrder(key)
	if err != nil {
		return "", err
	}
	letters := transpositionLetters(text)
	width := len(order)
	var out strings.Builder
	for _, col := range order {
		for row := 0; col+row*width < len(letters); row++ {
			out.WriteByte(letters[col+row*width])
		}
	}
	return out.String(), nil
}

func decodeColumnar(text, key string) (string, error) {
	order, err := columnarOrder(key)
	if err != nil {
		return "", err
	}
	letters := transpositionLetters(text)
	width := len(order)
	if width == 0 {
		return "", errors.New("a columnar key needs at least two characters")
	}
	// Columns are not all the same height when the message does not fill
	// the rectangle, and getting that wrong shifts every column after the
	// first short one.
	full, short := len(letters)/width, len(letters)%width
	height := make([]int, width)
	for c := 0; c < width; c++ {
		height[c] = full
		if c < short {
			height[c]++
		}
	}
	columns := make([][]byte, width)
	at := 0
	for _, col := range order {
		columns[col] = []byte(letters[at : at+height[col]])
		at += height[col]
	}
	var out strings.Builder
	for row := 0; row < full+1; row++ {
		for col := 0; col < width; col++ {
			if row < len(columns[col]) {
				out.WriteByte(columns[col][row])
			}
		}
	}
	return out.String(), nil
}

// ── Scytale ───────────────────────────────────────────────────────────────────

// The scytale is the oldest cipher device anyone has named: a strip of leather
// wound round a rod, written across the turns, and unreadable until it is
// wound round a rod of the same thickness. The rod's thickness is the key, and
// it is the -r flag here because that is the same shape of parameter as the
// rail fence's.
func encodeScytale(text string, turns int) (string, error) {
	if turns < 2 {
		return "", errors.New("a scytale needs a rod of at least two, given with -r")
	}
	letters := []rune(text)
	var out strings.Builder
	for start := 0; start < turns; start++ {
		for i := start; i < len(letters); i += turns {
			out.WriteRune(letters[i])
		}
	}
	return out.String(), nil
}

func decodeScytale(text string, turns int) (string, error) {
	if turns < 2 {
		return "", errors.New("a scytale needs a rod of at least two, given with -r")
	}
	letters := []rune(text)
	n := len(letters)
	if n == 0 {
		return "", nil
	}
	full, short := n/turns, n%turns
	out := make([]rune, n)
	at := 0
	for start := 0; start < turns; start++ {
		height := full
		if start < short {
			height++
		}
		for row := 0; row < height; row++ {
			out[start+row*turns] = letters[at]
			at++
		}
	}
	return string(out), nil
}

// ── ADFGVX ────────────────────────────────────────────────────────────────────

// adfgvxLetters are the six the cipher is named after. They were not chosen
// for secrecy: in Morse they are as unlike each other as six letters get, so a
// garbled wireless transmission was less likely to turn one into another.
const adfgvxLetters = "ADFGVX"

func adfgvxKeys(key string) (string, string, error) {
	parts := strings.SplitN(key, ",", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("an ADFGVX key is the square's key phrase and the transposition key, separated by a comma: -k privacy,german")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

// ADFGVX is a fractionating cipher followed by a transposition: each character
// becomes two letters from a six-by-six square, and the resulting stream is
// then transposed under a second key. Splitting each character in two and then
// moving the halves apart is what made it hard — and it was broken anyway, by
// Painvin in 1918, on traffic volume alone.
func encodeADFGVX(text, key string) (string, error) {
	squareKey, transKey, err := adfgvxKeys(key)
	if err != nil {
		return "", err
	}
	_, index, err := polybiusSquare(squareKey, 6)
	if err != nil {
		return "", err
	}
	var pairs strings.Builder
	for _, c := range polybiusLetters(text, 6) {
		rc := index[c]
		pairs.WriteByte(adfgvxLetters[rc[0]])
		pairs.WriteByte(adfgvxLetters[rc[1]])
	}
	return encodeColumnar(pairs.String(), transKey)
}

func decodeADFGVX(text, key string) (string, error) {
	squareKey, transKey, err := adfgvxKeys(key)
	if err != nil {
		return "", err
	}
	square, _, err := polybiusSquare(squareKey, 6)
	if err != nil {
		return "", err
	}
	pairs, err := decodeColumnar(text, transKey)
	if err != nil {
		return "", err
	}
	pairs = strings.ToUpper(pairs)
	if len(pairs)%2 != 0 {
		return "", errors.New("an ADFGVX message is a whole number of letter pairs, and this one is not")
	}
	var out strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		row := strings.IndexByte(adfgvxLetters, pairs[i])
		col := strings.IndexByte(adfgvxLetters, pairs[i+1])
		if row < 0 || col < 0 {
			return "", fmt.Errorf("%q is not one of the six letters this cipher uses", pairs[i:i+2])
		}
		out.WriteByte(square[row*6+col])
	}
	return out.String(), nil
}
