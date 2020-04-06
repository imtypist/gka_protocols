# Group key agreement protocols

This repo implements five basic GKA protocols by C language. The code is from `CLIQUE 1.0`, which was not maintained since 2002. I upgrade the version of OpenSSL used in this project to `1.1.1` that is a long-term support version.

## Project tree

```
- bd/      # BD protocol
- clq/     # CLQ(GDH) and CKD protocols
- str/     # STR protocol
- tgdh/    # TGDH protocol
- common/  # Some common components
- utils/   # Used to generate certificates
```