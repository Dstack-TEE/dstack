#!/bin/sh
# BUG: https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2056555
sudo apparmor_parser -R /etc/apparmor.d/unprivileged_userns
