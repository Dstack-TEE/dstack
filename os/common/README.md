# Common guest rootfs payload

`rootfs/` contains files installed into every dstack guest independently of the
OS build backend. It is intentionally separate from Rust application source and
from Yocto recipes.

A backend should stage these files into their documented destinations. Keep
the payload canonical here and add a backend-specific installer rather than
copying the files. The default mkosi backend installs them in
`../mkosi/components/dstack-rust/dstack-rust-build.sh`; the deprecated Yocto
backend's mapping is in
`../yocto/layers/meta-dstack/recipes-core/dstack-guest/dstack-guest.bb`.

`nvidia/` holds the NVIDIA payload both backends stage: the topology probe, the
module-option generator and its unit, the udev autoload blacklist, and the two
unit files that are conditional on GPU/NVSwitch presence. It lives here rather
than in the Yocto layer because the mkosi backend installs the same files, and
reaching across backends for them made it easy to change one and forget the
other.
