# Paillier encryption

This is a fork of [libpaillier](http://acsc.cs.utexas.edu/libpaillier/) implemented by John Bethencourt. Please see original [README](./README).


## Installation

Make sure [GMP](https://gmplib.org/) is installed.

```sh
$ ./configure
$ make
```

## Running Tests

```sh
$ gcc -O3 test.c paillier.o -lgmp -o test -std=gnu11
$ ./test
```

## Running Benchmarks

```sh
$ gcc -O3 bench.c paillier.o -lgmp -o bench -std=gnu11
$ ./bench
```