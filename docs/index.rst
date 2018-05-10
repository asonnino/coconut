.. Coconut documentation master file, created by
   sphinx-quickstart on Wed May  9 10:02:04 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Coconut's documentation! 
===================================

.. image:: https://img.shields.io/badge/license-BSD-brightgreen.svg
    :target: https://github.com/asonnino/coconut/blob/master/LICENSE

.. image:: https://travis-ci.org/asonnino/coconut.svg?branch=master
    :target: https://travis-ci.org/asonnino/coconut

.. image:: https://readthedocs.org/projects/coconut-lib/badge/?version=latest
    :target: https://readthedocs.org/projects/coconut-lib/?badge=latest
    :alt: Documentation Status


**Coconut** is a novel selective disclosure credential scheme supporting distributed threshold issuance, public and private attributes, re-randomization, and multiple unlinkable selective attribute revelations. Coconut integrates with blockchains to ensure confidentiality, authenticity and availability even when a subset of credential issuing authorities are malicious or offline. Coconut uses short and computationally efficient credentials, and our evaluation_ shows that most Coconut cryptographic primitives take just a few milliseconds on average, with verification taking the longest time (10 milliseconds). We implement and evaluate a generic Coconut smart contract library for Chainspace_ and Ethereum_.

A link to the full paper is available here_. 

.. _evaluation: https://github.com/asonnino/coconut-timing
.. _Chainspace: https://github.com/asonnino/coconut-chainspace
.. _Ethereum: https://github.com/asonnino/coconut-ethereum
.. _here: https://arxiv.org/abs/1802.07344](https://arxiv.org/abs/1802.07344


Pre-requisites
--------------
**Coconut** is built on top of petlib_ and bplib_, make sure to follow `these instructions`_ to install all the pre-requisites.

.. _petlib: https://github.com/gdanezis/petlib
.. _bplib: https://github.com/gdanezis/bplib
.. _`these instructions`: https://github.com/gdanezis/petlib#pre-requisites


Install
-------

If you have `pip` installed, you can install **Coconut** with the following command:

.. code-block:: none
   
   pip install coconut-lib


otherwise, you can build it manually as below:

.. code-block:: none

    git clone https://github.com/asonnino/coconut
    cd coconut
    pip install -e .


Test
----

Tests can be run as follows:

.. code-block:: none

	pytest -v --cov=coconut tests/

or simply using tox:

.. code-block:: none

	tox


Coconut Modules
---------------
.. automodule:: coconut

.. automodule:: coconut.scheme

.. autofunction:: coconut.scheme.setup

.. autofunction:: coconut.scheme.ttp_keygen

.. autofunction:: coconut.scheme.aggregate_vk

.. autofunction:: coconut.scheme.prepare_blind_sign

.. autofunction:: coconut.scheme.blind_sign

.. autofunction:: coconut.scheme.unblind

.. autofunction:: coconut.scheme.aggregate_sigma

.. autofunction:: coconut.scheme.randomize

.. autofunction:: coconut.scheme.show_blind_sign

.. autofunction:: coconut.scheme.blind_verify


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


License
-------
`The BSD license`_ 

.. _`The BSD license`: https://opensource.org/licenses/BSD-3-Clause

