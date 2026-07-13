#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: BUSL-1.1

# BUG: https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2056555
sudo apparmor_parser -R /etc/apparmor.d/unprivileged_userns
