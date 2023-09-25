#!/bin/sh
sed -i 's/;I;/;/g' $1 
sed -i 's/;4;/ A/g' $1 
sed -i 's/;6;/ AAAA/g' $1 



