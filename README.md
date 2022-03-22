# Python Bitsliced AES

An experimental implementation of bitsliced AES-128-ECB in pure python. Quite possibly the fastest pure-python AES implementation on the planet.

Bitslice AES logic based on https://github.com/conorpp/bitsliced-aes. Thanks to `someone12469` for the bit packing trick.

This is currently just a performance test, it has not been rigourously evaluated from a security perspective.

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
Size: 0x10 bytes. Speed: 0.010748708616940834 MB/s
Size: 0x100 bytes. Speed: 0.20518680839274817 MB/s
Size: 0x200 bytes. Speed: 0.3675134687165803 MB/s
Size: 0x400 bytes. Speed: 0.7493836462514636 MB/s
Size: 0x800 bytes. Speed: 1.476730332109973 MB/s
Size: 0x1000 bytes. Speed: 2.71460696086907 MB/s
Size: 0x10000 bytes. Speed: 9.777050554537222 MB/s
Size: 0x100000 bytes. Speed: 13.119903169673073 MB/s
Size: 0x400000 bytes. Speed: 7.310395026532739 MB/s
Size: 0x1000000 bytes. Speed: 7.216789286347978 MB/s
```

Obviously, the optimal message length is around 1MB. I'm not quite sure why it slows
down for longer messages, but I believe its happening in the bitslice packing/unpacking process.
Longer messages could be broken up into shorter blocks, for optimal performance.

For reference, the next fastest pure-python AES implementation I could find was https://github.com/ricmoo/pyaes.
It runs at about 0.5MB/s (or with some of my own optimisations, about 0.75MB/s).

This bitsliced implementation is an order of magnitude faster (although, only on inputs longer than about 1024 bytes).
