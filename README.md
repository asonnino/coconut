# Coconut

[![license](https://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/asonnino/coconut/blob/master/LICENSE) 
[![Build Status](https://travis-ci.org/asonnino/coconut.svg?branch=master)](https://travis-ci.org/asonnino/coconut)
[![Documentation Status](https://readthedocs.org/projects/coconut-lib/badge/?version=latest)](http://coconut-lib.readthedocs.io/en/latest/?badge=latest)

Coconut is selective disclosure credential scheme supporting distributed threshold issuance, public and private attributes, re-randomization, and multiple unlinkable selective attribute revelations. Coconut can be used by modern blockchains to ensure confidentiality, authenticity and availability even when a subset of credential issuing authorities are malicious or offline. Coconut uses short and computationally efficient credentials, and our evaluation shows that most Coconut cryptographic primitives take just a few milliseconds on average, with verification taking the longest time (10 milliseconds).


## Pre-requisites
**Coconut** is built on top of [petlib](https://github.com/gdanezis/petlib) and [bplib](https://github.com/gdanezis/bplib), make sure to follow [these instructions](https://github.com/gdanezis/petlib#pre-requisites) to install all the pre-requisites.


## Install
If you have `pip` installed, you can install **Coconut** with the following command:
```
$ pip install coconut-lib
```
otherwise, you can build it manually as below:
```
$ git clone https://github.com/asonnino/coconut
$ cd coconut
$ pip install -e .
```


## Test
Tests can be run as follows:
```
$ pytest -v --cov=coconut tests/
```
or simply using tox:
```
$ tox
```

## License
[The BSD license](https://opensource.org/licenses/BSD-3-Clause)
