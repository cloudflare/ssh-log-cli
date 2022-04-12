# SSH Log CLI

CLI tool that decrypts and decodes session replay files captured by Cloudflare's Audit SSH proxy.

## Installation

### Build from source
1. Install Rust https://doc.rust-lang.org/cargo/getting-started/installation.html;
2. Run `cargo build --release`;
3. Find the compiled binary within `target/release/ssh-log-cli`.

## Generating a key pair

``` shell
$ ssh-log-cli generate-key-pair -o <PRIVATE KEY FILE NAME>
```

This command generates an HPKE public and private key, saving each one to its own file. The public key file gets the same name, but with a `.pub` extension.

#
## Handling SSH session capture files

### Decrypting and parsing any SSH session capture file
``` shell
$ ssh-log-cli decrypt -i <PATH TO INPUT FILE> -k <PATH TO HPKE private key> [-o <PATH TO OUTPUT FILE>]
```

 If no output file name is specified, it defaults it to <encrypted_file_name>.decrypted.zip.

**Note**: the output file path must be a valid ZIP file name.

### Decrypting and replaying an SSH PTY session capture file — *Linux/Mac OS X only*
``` shell
$ ssh-log-cli decrypt -i <PATH TO INPUT FILE> -k <PATH TO HPKE private key> --replay
```
 
 This will decrypt the session capture and replay it to *stdout*.
 
 **Note**: no output file will be generated.
#
## Understanding the Output
 
### PTY Sessions
If the encrypted file has a valid interactive session (PTY) capture, then the output ZIP will contain 2 files:
`term_data.txt` and `term_times.txt`.
 
You can then extract it and either open term_data.txt and analyse it on your own or watch a replay by running:
`scriptreplay --timing term_times.txt term_data.txt`
 
### Non-PTY Sessions
If the encrypted file has a valid non-PTY session capture, then the output ZIP will contain 2 files:
`data_from_client.txt` and `data_from_server.txt`. These contain upstream and downstream traffic, respectively.
