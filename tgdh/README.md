# TGDH

## Compile

```bash
$ make
```

## Test

Please make sure your `bin` folder contains `*_cert.pem`, `*_priv.pem`, `cacert.pem`, `dsa_param.pem`, or you can set the path as `export var=/path/to/these/files`. You can read source code for more details.

```bash
$ ./tgdh_test <#member> <#round>
```