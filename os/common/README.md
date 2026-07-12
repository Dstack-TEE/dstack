# Common guest rootfs payload

`rootfs/` contains files installed into every dstack guest independently of the
OS build backend. It is intentionally separate from Rust application source and
from Yocto recipes.

A backend should stage these files into their documented destinations. The
current authoritative mapping is in
`../yocto/layers/meta-dstack/recipes-core/dstack-guest/dstack-guest.bb`. When a
second backend is introduced, keep the payload canonical here and add a
backend-specific installer rather than copying the files.
