package main

import "strings"

var base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NATO phonetic alphabet — letter/digit → word
var natoAlphabet = map[rune]string{
	'A': "Alpha", 'B': "Bravo", 'C': "Charlie", 'D': "Delta", 'E': "Echo",
	'F': "Foxtrot", 'G': "Golf", 'H': "Hotel", 'I': "India", 'J': "Juliet",
	'K': "Kilo", 'L': "Lima", 'M': "Mike", 'N': "November", 'O': "Oscar",
	'P': "Papa", 'Q': "Quebec", 'R': "Romeo", 'S': "Sierra", 'T': "Tango",
	'U': "Uniform", 'V': "Victor", 'W': "Whiskey", 'X': "X-ray", 'Y': "Yankee",
	'Z': "Zulu",
	'0': "Zero", '1': "One", '2': "Two", '3': "Three", '4': "Four",
	'5': "Five", '6': "Six", '7': "Seven", '8': "Eight", '9': "Nine",
}

// natoWordSet is the set of all lowercase NATO words for fast O(1) lookup.
var natoWordSet = buildNATOWordSet()

func buildNATOWordSet() map[string]bool {
	set := make(map[string]bool, len(natoAlphabet))
	for _, word := range natoAlphabet {
		set[strings.ToLower(word)] = true
	}
	return set
}

// reverseNATO maps lowercase NATO word → original character (uppercase letter or digit).
var reverseNATO = buildReverseNATO()

func buildReverseNATO() map[string]rune {
	out := make(map[string]rune, len(natoAlphabet))
	for ch, word := range natoAlphabet {
		out[strings.ToLower(word)] = ch
	}
	return out
}

var morseMap = map[rune]string{
	'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".", 'F': "..-.", 'G': "--.",
	'H': "....", 'I': "..", 'J': ".---", 'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.",
	'O': "---", 'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-", 'U': "..-",
	'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--", 'Z': "--..",
	'0': "-----", '1': ".----", '2': "..---", '3': "...--", '4': "....-", '5': ".....",
	'6': "-....", '7': "--...", '8': "---..", '9': "----.",
	'.': ".-.-.-", ',': "--..--", '?': "..--..", '!': "-.-.--", '/': "-..-.", '-': "-....-", '(': "-.--.", ')': "-.--.-",
	' ': "/",
}

var reverseMorse = buildReverseMorse()

func buildReverseMorse() map[string]rune {
	out := make(map[string]rune, len(morseMap))
	for k, v := range morseMap {
		out[v] = k
	}
	return out
}
