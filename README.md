# BHZTK_aes-gcm
library and cli tool to encrypt an decrypt files or strings using aes-gcm


tools:

gcc version 13.1.0 (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders)

Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)] on win32


                                    #input array

    # index      variable         type                        info

    #  0          = key            bytes            (len must be either 16 or 24 or 32 )

    #  1          = header         bytes            (optional, dont need to be unique)

    #  2          = data           bytes            (data to be encrypted, if size exceeds MAX_MEMORY_USAGE it will be encrypted in chunks)

    #  3          = nonce          bytes            (must be unique for every pair of message+key)

    #  4          = tag            bytes            (MAC tag)

    #  5          = mac len        int              ([>=4; >=16])

    #  6          = filename       str              (path of input file)

    #  7          = mode           str              (encryption = "enc"; decryption = "dec")
