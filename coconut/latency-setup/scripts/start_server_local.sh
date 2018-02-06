#!/bin/bash

N=10
echo ">> runing $N on ports 5000 -- $((5000 + N - 1)) ..."

for ((i=0;i<N;i++)); do
	python server.py $((5000+i)) &
done
echo ">> Done."