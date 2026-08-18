#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

target=${DSTACK_TEST_HUGEPAGES_2M_TARGET:-512}
sysfs=/sys/kernel/mm/hugepages/hugepages-2048kB

[[ $target =~ ^[1-9][0-9]*$ ]] || {
  printf 'invalid 2 MiB hugepage target: %s\n' "$target" >&2
  exit 1
}
[[ -r $sysfs/nr_hugepages && -r $sysfs/free_hugepages ]] || {
  printf '2 MiB hugepage sysfs controls are unavailable\n' >&2
  exit 1
}
findmnt -rn -T /dev/hugepages -t hugetlbfs >/dev/null || {
  printf 'hugetlbfs is not mounted at /dev/hugepages\n' >&2
  exit 1
}

total=$(<"$sysfs/nr_hugepages")
if (( total < target )); then
  sudo sysctl -q -w "vm.nr_hugepages=$target"
fi
total=$(<"$sysfs/nr_hugepages")
free=$(<"$sysfs/free_hugepages")
if (( total < target || free < target )); then
  printf 'insufficient free 2 MiB hugepages after preparation: total=%s free=%s target=%s\n' \
    "$total" "$free" "$target" >&2
  exit 1
fi
printf 'prepared 2 MiB hugepages: total=%s free=%s target=%s\n' "$total" "$free" "$target"
