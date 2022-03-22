# python-bitsliced-aes
An experimental implementation of bitsliced aes in pure python. Quite possibly the fastest pure-python AES implementation on the planet.

Bitslice AES logic based on https://github.com/conorpp/bitsliced-aes. Thanks to `someone12469` for the bit packing trick.

Benchmark results from an M1 Pro macbook:

```
Size: 0x10 bytes. Speed: 0.00979213948158905 MB/s
Size: 0x100 bytes. Speed: 0.2033569630731888 MB/s
Size: 0x200 bytes. Speed: 0.3661175784327935 MB/s
Size: 0x400 bytes. Speed: 0.7431157773410884 MB/s
Size: 0x800 bytes. Speed: 1.4439644713729343 MB/s
Size: 0x1000 bytes. Speed: 2.6039894565041872 MB/s
Size: 0x10000 bytes. Speed: 8.098923491089558 MB/s
Size: 0x100000 bytes. Speed: 11.94128913542198 MB/s
Size: 0x400000 bytes. Speed: 7.914459860922976 MB/s
Size: 0x1000000 bytes. Speed: 7.02089122658765 MB/s
```

Benchmark results from an AMD 3950x:

```
TODO
```
