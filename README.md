# DSigner
Tool to add Digital Signature using signtool.exe with SHA-1, SHA-2 or Dual, able to apply white and black list.

## License
[MIT](https://github.com/18konoe/DSigner/blob/master/LICENSE)

## Usage

  Usage: DSigner <command> <-f|-d target> [options...]  
  ### command
    SHA1                 Only SHA-1 signing  
    SHA2                 Only SHA-2 signing  
    Dual                 SHA-1 + SHA-2 signing  

  ### target
    -f <file path>       Only 1 file signing  
    -d <directory path>  All files signed in specified directory  

  ### option
    -w <whitelist(json)> Use white list if match listed regular expressions  
    -b <blacklist(json)> Use black list if match listed regular expressions  
