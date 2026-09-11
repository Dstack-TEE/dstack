// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{build, Error, MachineConfig, QemuVersion};

    fn config(nics: u32, volumes: u32) -> MachineConfig {
        MachineConfig {
            qemu_version: QemuVersion::new(11, 1, 0),
            cpu_count: 1,
            memory_size: 2 << 30,
            pic: false,
            smm: false,
            hugepages: false,
            num_gpus: 0,
            num_nvswitches: 0,
            num_nics: nics,
            num_verity_volumes: volumes,
            hotplug_off: false,
            root_verity: true,
            pci_hole64_size: None,
        }
    }

    #[test]
    fn one_nic_matches_qemu_byte_for_byte() -> Result<(), Error> {
        let actual = build(&config(1, 0))?;
        assert_eq!(
            actual.tables,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic.bin")
        );
        assert_eq!(
            actual.loader,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic-loader.bin")
        );
        assert_eq!(
            actual.rsdp,
            include_bytes!("../fixtures/qemu-11.1-q35-one-nic-rsdp.bin")
        );
        Ok(())
    }

    #[test]
    fn no_gpu_hotplug_off_matches_qemu_byte_for_byte() -> Result<(), Error> {
        let mut c = config(0, 0);
        c.hotplug_off = true;
        let actual = build(&c)?;
        let expected = include_bytes!("../fixtures/qemu-11.1-q35-hotplug-off-base.bin");
        assert_eq!(&actual.tables[..expected.len()], *expected);
        assert!(actual.tables[expected.len()..]
            .iter()
            .all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn numa_loader_and_rsdp_match_qemu_byte_for_byte() -> Result<(), Error> {
        let mut numa = config(1, 0);
        numa.hugepages = true;
        let actual = build(&numa)?;
        assert_eq!(
            actual.loader,
            include_bytes!("../fixtures/qemu-11.1-q35-numa-one-nic-loader.bin")
        );
        assert_eq!(
            actual.rsdp,
            include_bytes!("../fixtures/qemu-11.1-q35-numa-one-nic-rsdp.bin")
        );
        Ok(())
    }

    fn qemu_hash(config: MachineConfig) -> Result<String, Error> {
        use sha2::{Digest, Sha256};

        // Keep ownership local so callers can conveniently vary the config.
        config.validate()?;
        Ok(hex::encode(Sha256::digest(build(&config)?.tables)))
    }

    #[test]
    fn qemu_version_and_cpu_goldens() -> Result<(), Error> {
        let versions = [
            (
                (8, 2, 0),
                "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6",
            ),
            (
                (9, 1, 0),
                "ff0c03c7f4026a95b0b2f2e08cef7d501a3a44b4df036c9f26de91828f0215f6",
            ),
            (
                (9, 2, 1),
                "b183eba66c6e96556f28cefe60ca92620b82488fcefaf66167aad61e2b2e73d1",
            ),
            (
                (10, 0, 0),
                "d0410a8abdbba6d86a19a2eefd491376727e4e2d80c54349d7f30deca14ca6e1",
            ),
            (
                (11, 0, 0),
                "e211dd453e651ef320d28c65d23f578e96468614614e7b1172f18df5052d0f1f",
            ),
            (
                (11, 1, 0),
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
        ];
        for ((major, minor, micro), expected) in versions {
            let mut c = config(1, 0);
            c.qemu_version = QemuVersion::new(major, minor, micro);
            assert_eq!(qemu_hash(c)?, expected);
        }

        let cpus = [
            (
                1,
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
            (
                2,
                "1362c6f473801b34f93df4e2966b2d3350f7f9113750da78a2cb799177157da8",
            ),
            (
                8,
                "0f9fc08c5efd03f1cb3cfaa1a0a09c45dcfbc18183dbc5aa1367ad10eb65135a",
            ),
            (
                64,
                "089fda95fb5d45ba9a5f46ebc99d85e1331daa4dd38f60597eec9a3d95c94bb5",
            ),
            (
                256,
                "d1c3291dbdf0ccc4acdecce5f78fbe80e0ca7d6d803a62c9f5b59ee8c7e0a1b5",
            ),
            (
                4096,
                "6a4bbd704addd10996632d6535432598c742789e60b29d055a7784be927588a5",
            ),
        ];
        for (count, expected) in cpus {
            let mut c = config(1, 0);
            c.cpu_count = count;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn qemu_device_count_goldens() -> Result<(), Error> {
        let cases = [
            (
                0,
                0,
                0,
                0,
                "93a140bbc031dc313ed4011b838c8b22ffdecb474435d9fcb294be97194c953c",
            ),
            (
                1,
                0,
                0,
                0,
                "09f99e5dcf36b80a9258e849b3a9a70e7914244008e6a92a689eb22e4cc17a8f",
            ),
            (
                2,
                0,
                0,
                0,
                "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64",
            ),
            (
                1,
                1,
                0,
                0,
                "fbf083121cc3b46b3b7913e45e635e6bb31e11f0cb6e029aa504bc4de68e2d64",
            ),
            (
                1,
                4,
                0,
                0,
                "7d722d7e3d811aa7978030af1d2a6c6aa68a5ab9267d7dff4e57babdf1476870",
            ),
            (
                1,
                0,
                1,
                0,
                "f22f486b0e33ed0aad80e6cb26726652d671d3c58f521827825a26f069e499a3",
            ),
            (
                1,
                0,
                8,
                0,
                "037b07a2b0d6dc1d3b8370bb8d84564b74cd4f9a09163252c4a8b08d9ad0be70",
            ),
            (
                1,
                0,
                1,
                1,
                "6f1e598f7b9acbc24c33c573c81112b4e9df7d576d18e82d94b0253c4a69da71",
            ),
            (
                1,
                0,
                1,
                4,
                "e23873ce836a73783d043173f9757da1b36151a3a2987c8ab978e33570120eb9",
            ),
        ];
        for (nics, volumes, gpus, switches, expected) in cases {
            let mut c = config(nics, volumes);
            c.num_gpus = gpus;
            c.num_nvswitches = switches;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn qemu_memory_layout_boundaries() -> Result<(), Error> {
        let cases = [
            (
                1,
                "8d7620126cfd2a2edabbc8c9f289ca2993f547d595eed61fd508d24f2b52e3ac",
            ),
            (
                2049,
                "646e5cc620fd7819f8f4756c712619d2a72c29a175fc04b79867cee80e67cf82",
            ),
            (
                2815,
                "ee35c5e548a3f527dd12b1dd6ee14e093fd6063056470b3ef6cb6c844e4186a4",
            ),
            (
                2816,
                "3bf181108245994ceb7e983b1fa62009dcd56f7b49fd1e96ef15eb07d04aefc9",
            ),
            (
                1_048_576,
                "f22a114b0975b18200553442d6c9fab172fb930252c1a95926c594b2c25bca57",
            ),
        ];
        for (mib, expected) in cases {
            let mut c = config(1, 0);
            c.cpu_count = 2;
            c.memory_size = mib * 1024 * 1024;
            c.hugepages = true;
            c.num_gpus = 1;
            assert_eq!(qemu_hash(c)?, expected);
        }
        Ok(())
    }

    #[test]
    fn pxb_supports_qemus_full_gpu_range() -> Result<(), Error> {
        for gpus in [1, 8, 32] {
            let mut c = config(1, 0);
            c.hugepages = true;
            c.num_gpus = gpus;
            assert_eq!(
                qemu_hash(c)?,
                "a8449287b161102ca136f892d13d6bc853d1abdc9ba7804e886f0a42784878c3"
            );
        }
        Ok(())
    }

    #[test]
    fn device_kinds_share_qemus_slot_allocation() -> Result<(), Error> {
        assert_eq!(build(&config(5, 0))?.tables, build(&config(1, 4))?.tables);
        Ok(())
    }

    #[test]
    fn hostile_counts_are_rejected_without_generation() {
        let mut c = config(u32::MAX, u32::MAX);
        c.cpu_count = u32::MAX;
        c.num_gpus = u32::MAX;
        c.num_nvswitches = u32::MAX;
        assert!(crate::build(&c).is_err());

        let mut c = config(1, 0);
        c.cpu_count = 0;
        assert!(crate::build(&c).is_err());

        let mut c = config(1, 0);
        c.memory_size = 0;
        assert!(crate::build(&c).is_err());
    }

    #[test]
    fn validated_boundary_inputs_generate_safely() -> Result<(), Error> {
        for version in [
            QemuVersion::new(8, 0, 0),
            QemuVersion::new(9, 1, 0),
            QemuVersion::new(9, 2, 0),
            QemuVersion::new(10, 0, 0),
            QemuVersion::new(11, 0, 0),
            QemuVersion::new(11, 1, 0),
        ] {
            for cpus in [1, 255, 256, 4096] {
                for memory_size in [1, 0xafff_ffff, 0xb000_0000, u64::MAX] {
                    let mut c = config(0, 0);
                    c.qemu_version = version;
                    c.cpu_count = cpus;
                    c.memory_size = memory_size;
                    c.pci_hole64_size = Some(u64::MAX);
                    crate::build(&c)?;
                }
            }
        }
        Ok(())
    }
}
