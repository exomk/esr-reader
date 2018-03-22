#!/bin/sh

echo "****************************************************************"
echo "Autogenerate build scripts for ESR reader"

aclocal
autoconf
automake --add-missing
