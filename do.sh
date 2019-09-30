#! /bin/bash
git checkout debian/rules
patch -p1 < ./disable_dh_aut_test.diff
buildtype=release debuild -b -uc -us
