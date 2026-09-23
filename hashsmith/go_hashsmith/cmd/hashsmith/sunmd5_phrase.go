package main

// The 1,517 bytes SunMD5 mixes in on roughly half its rounds: Hamlet's
// soliloquy, from Project Gutenberg, including the trailing NUL that the C
// string constant carries and the implementation hashes along with the text.
//
// It is here for the reason a nothing-up-my-sleeve number usually is, and it
// does its job in an unusual way: because it is added only when a coin flip
// says so, the amount of work a password costs depends on the password. Half
// the rounds hash sixteen bytes and half hash a kilobyte and a half, and which
// is which is not knowable in advance. That was the point — it defeats the
// fixed-size pipelining a fast MD5 implementation relies on.

const sunMD5ConstantPhrase = "To be, or not to be,--that is the question:--\nWhether 'tis nobler in the " +
	"mind to suffer\nThe slings and arrows of outrageous fortune\nOr to take ar" +
	"ms against a sea of troubles,\nAnd by opposing end them?--To die,--to slee" +
	"p,--\nNo more; and by a sleep to say we end\nThe heartache, and the thousa" +
	"nd natural shocks\nThat flesh is heir to,--'tis a consummation\nDevoutly t" +
	"o be wish'd. To die,--to sleep;--\nTo sleep! perchance to dream:--ay, ther" +
	"e's the rub;\nFor in that sleep of death what dreams may come,\nWhen we ha" +
	"ve shuffled off this mortal coil,\nMust give us pause: there's the respect" +
	"\nThat makes calamity of so long life;\nFor who would bear the whips and s" +
	"corns of time,\nThe oppressor's wrong, the proud man's contumely,\nThe pan" +
	"gs of despis'd love, the law's delay,\nThe insolence of office, and the sp" +
	"urns\nThat patient merit of the unworthy takes,\nWhen he himself might his" +
	" quietus make\nWith a bare bodkin? who would these fardels bear,\nTo grunt" +
	" and sweat under a weary life,\nBut that the dread of something after deat" +
	"h,--\nThe undiscover'd country, from whose bourn\nNo traveller returns,--p" +
	"uzzles the will,\nAnd makes us rather bear those ills we have\nThan fly to" +
	" others that we know not of?\nThus conscience does make cowards of us all;" +
	"\nAnd thus the native hue of resolution\nIs sicklied o'er with the pale ca" +
	"st of thought;\nAnd enterprises of great pith and moment,\nWith this regar" +
	"d, their currents turn awry,\nAnd lose the name of action.--Soft you now!" +
	"\nThe fair Ophelia!--Nymph, in thy orisons\nBe all my sins remember'd.\n\x00"
