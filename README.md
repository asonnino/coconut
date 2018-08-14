# Coconut

[![license](https://img.shields.io/badge/license-apache2-brightgreen.svg)](https://github.com/asonnino/coconut/blob/master/LICENSE) 
[![Build Status](https://travis-ci.org/asonnino/coconut.svg?branch=master)](https://travis-ci.org/asonnino/coconut)
[![Documentation Status](https://readthedocs.org/projects/coconut-lib/badge/?version=latest)](http://coconut-lib.readthedocs.io/en/latest/?badge=latest)

**Coconut** is a novel selective disclosure credential scheme supporting distributed threshold issuance, public and private attributes, re-randomization, and multiple unlinkable selective attribute revelations. Coconut integrates with blockchains to ensure confidentiality, authenticity and availability even when a subset of credential issuing authorities are malicious or offline. Coconut uses short and computationally efficient credentials, and our [evaluation](https://github.com/asonnino/coconut-timing) shows that most Coconut cryptographic primitives take just a few milliseconds on average, with verification taking the longest time (10 milliseconds). We implement and evaluate a generic Coconut smart contract library for [Chainspace](https://github.com/asonnino/coconut-chainspace) and [Ethereum](https://github.com/asonnino/coconut-ethereum).

A link to the full paper is available at the following address: [https://arxiv.org/abs/1802.07344](https://arxiv.org/abs/1802.07344)


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
[The Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0)
