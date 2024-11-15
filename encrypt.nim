import nimcrypto
import std/[sequtils, strformat, json]

#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause

    AES256-CTR Encryption/Decryption

    Edits: Get shellcode from file and then encrypt it in an output file. Also putting IV and KEY in "constants.json" file in the same directory.
]#

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc main() = 
  let shellcode = readFile("shellcode.bin") # TO EDIT
  echo fmt"[i] Shellcode length : {shellcode.len}"

  var
      data: seq[byte] = toByteSeq(shellcode)
      envkey: string = "AAAAAAAAAAAA" # TO EDIT
      ectx: CTR[aes256]
      key: array[aes256.sizeKey, byte]
      iv: array[aes256.sizeBlock, byte]
      plaintext = newSeq[byte](len(data))
      enctext = newSeq[byte](len(data))
      constant = %* { "IV": toSeq(iv), "KEY": toSeq(key)}

  discard randomBytes(addr iv[0], 16)
  copyMem(addr plaintext[0], addr data[0], len(data))
  # Expand key to 32 bytes using SHA256 as the KDF
  var expandedkey = sha256.digest(envkey)
  copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

  ectx.init(key, iv)
  ectx.encrypt(plaintext, enctext)
  ectx.clear()

  echo "IV: ", toHex(iv)
  echo "KEY: ", expandedkey
  echo "PLAINTEXT: "
  for element in plaintext:
    stdout.write fmt("{element:02X}")
  stdout.write("\n")

  echo "ENCRYPTED TEXT: "
  for element in enctext:
    stdout.write fmt("{element:02X}")
  stdout.write("\n")

  constant = %* { "IV": iv, "KEY": expandedkey.data}
  echo "CONSTANTS: ", constant
  writeFile("constants.json", $constant)
  writeFile("sc_enc.bin", enctext)

main()