# crypt-tool
A command line tool for hashing passwords using your system's libcrypt

Output of `crypt-tool --help`:

```
Hashes one or more passwords from the terminal or stdin.
Usage: crypt-tool [<prefix> [<rounds>]]

Example command line session:

	$ crypt '$2b' 12
	Password: <password is typed, followed by Enter>
	Hash: $2b$12$Z0vgnP2jil4YioUAGsDwa.nIkRS.we6hBNHyy4WutXlPT3V5D/ktO
	Password: <Enter is pressed immediately>
	<program exits>
	$ 

<prefix> is a string, such as "$2b$", that selects an algorithm for
the generated password hashes.  See crypt(5) for a list of supported
algorithms.  If not specified, NULL is provided, which the manpage for
crypt_gensalt(3) says is supposed to select "the best available hashing
method", whatever that means.

<rounds> is the number of "rounds" of hashing to apply.  Only some
algorithms use this value, and the meaning depends on which algorithm is
selected.  If not specified, 0 is provided, which tells the selected
algorithm to use its best judgement.

The input behavior depends on whether or not stdin is a terminal.
```
