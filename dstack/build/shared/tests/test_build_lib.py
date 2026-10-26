# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise release orchestration without Docker or network access.

Run with: python3 -m unittest discover -s dstack/build/shared/tests -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
COMPONENTS = ("kms/dstack-app", "gateway/dstack-app", "verifier")
MOCK_DOCKER = r"""
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    log.write(json.dumps(args) + "\n")
if args[:2] == ["buildx", "build"]:
    stage = "builder" if "--target" in args else "final"
    if os.environ.get("FAIL_BUILD") == stage:
        sys.exit(1)
    if "--metadata-file" in args:
        with open(args[args.index("--metadata-file") + 1], "w") as out:
            json.dump({"containerimage.digest": "sha256:" + "1" * 64}, out)
elif args[0] == "run":
    stage = "builder" if args[4].endswith("-builder-temp") else "final"
    if os.environ.get("FAIL_EXTRACT") == stage:
        sys.exit(1)
    print("package=" + ("2" if os.environ.get("DRIFT") == stage else "1"))
"""


class BuildTests(unittest.TestCase):
    """Check the real component entry points with a recording Docker executable."""

    def setUp(self):
        """Create a minimal tracked checkout and an annotated release tag."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shared = self.root / "dstack/build/shared"
        shared.mkdir(parents=True)
        shutil.copy(ROOT / "dstack/build/shared/build-lib.sh", shared)
        for component in COMPONENTS:
            builder = self.root / "dstack" / component / "builder"
            (builder / "shared").mkdir(parents=True)
            shutil.copy(ROOT / "dstack" / component / "builder/build-image.sh", builder)
            (builder / "Dockerfile").write_text(
                "FROM debian:bookworm@sha256:" + "0" * 64 + "\n"
            )
            for name in ("pinned-packages.txt", "builder-pinned-packages.txt"):
                (builder / "shared" / name).write_text("package=1\n")
        self.git("init", "-q")
        self.git("add", ".")
        tree = self.git("write-tree")
        # Synthetic objects avoid depending on or overriding any Git identity.
        identity = "Build Fixture <fixture@example.invalid> 1700000000 +0000"
        self.commit = self.git(
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
            input=f"tree {tree}\nauthor {identity}\ncommitter {identity}\n\nFixture\n",
        )
        self.git("update-ref", "HEAD", self.commit)
        tag = self.git(
            "hash-object",
            "-t",
            "tag",
            "-w",
            "--stdin",
            input=f"object {self.commit}\ntype commit\ntag release\ntagger {identity}\n\nRelease\n",
        )
        self.git("update-ref", "refs/tags/release", tag)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(f"#!{sys.executable}\n" + MOCK_DOCKER)
        docker.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        self.metadata = self.root / "metadata.json"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "CALLS": str(self.calls),
            "GIT_REV": "release",
            "IMAGE_VERSION": "1.0",
            "PUSH": "",
            "OCI_TAR": "",
            "METADATA_FILE": "",
            "NO_CACHE": "",
            "FAIL_BUILD": "",
            "FAIL_EXTRACT": "",
            "DRIFT": "",
        }

    def git(self, *args, input=None):
        """Run Git only against the disposable fixture repository."""
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args],
            input=input,
            text=True,
        ).strip()

    def run_build(self, component="kms/dstack-app", **env):
        """Run a real entry point and return its result and recorded build calls."""
        self.calls.unlink(missing_ok=True)
        result = subprocess.run(
            [
                "bash",
                str(self.root / "dstack" / component / "builder/build-image.sh"),
                "example/probe:1.0",
                "example/probe:latest",
            ],
            env={**self.env, **env},
            text=True,
            capture_output=True,
        )
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        builds = [call for call in calls if call[:2] == ["buildx", "build"]]
        return result, builds

    def test_local_build_peels_annotated_tags(self):
        """All components resolve annotated tags and load only the two stages."""
        for component in COMPONENTS:
            with self.subTest(component=component):
                result, builds = self.run_build(component)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(builds), 2)
                for build in builds:
                    self.assertIn(f"DSTACK_REV={self.commit}", build)
                    self.assertIn("SOURCE_DATE_EPOCH=1700000000", build)
                    self.assertEqual(build.count("--output"), 1)
                    self.assertIn("type=docker,rewrite-timestamp=true", build)
                    self.assertNotIn("--metadata-file", build)

    def test_exports_are_separate_and_follow_validation(self):
        """A no-cache request does not force a fresh build after validation."""
        result, builds = self.run_build(
            PUSH="1",
            OCI_TAR=str(self.root / "image.tar"),
            METADATA_FILE=str(self.metadata),
            NO_CACHE="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(builds), 4)
        self.assertIn("--target", builds[0])
        self.assertNotIn("--target", builds[1])
        for build in builds[:2]:
            self.assertIn("--no-cache", build)
            self.assertNotIn("--metadata-file", build)
        for build in builds[2:]:
            self.assertEqual(build.count("--output"), 1)
            self.assertNotIn("--no-cache", build)
            self.assertNotIn("--target", build)
            self.assertNotIn("type=docker,rewrite-timestamp=true", build)
            self.assertIn("--metadata-file", build)
            self.assertIn("example/probe:1.0", build)
            self.assertIn("example/probe:latest", build)
        self.assertTrue(
            builds[2][builds[2].index("--output") + 1].startswith("type=oci,")
        )
        self.assertIn(
            "type=image,push=true,oci-mediatypes=true,rewrite-timestamp=true", builds[3]
        )
        self.assertTrue(self.metadata.exists())

    def test_failures_never_publish(self):
        """Build errors, extraction errors and either drifting list block export."""
        for variable in ("FAIL_BUILD", "FAIL_EXTRACT", "DRIFT"):
            for stage in ("final", "builder"):
                with self.subTest(variable=variable, stage=stage):
                    self.git("restore", ".")
                    result, builds = self.run_build(
                        PUSH="1",
                        METADATA_FILE=str(self.metadata),
                        **{variable: stage},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    for build in builds:
                        self.assertIn("type=docker,rewrite-timestamp=true", build)
                        self.assertNotIn("--metadata-file", build)
                    self.assertFalse(self.metadata.exists())

    def test_dirty_inputs_block_publication_before_building(self):
        """Extraction must not be allowed to erase dirty publication inputs."""
        pins = self.root / "dstack/kms/dstack-app/builder/shared/pinned-packages.txt"
        pins.write_text("package=2\n")
        result, builds = self.run_build(PUSH="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(builds, [])
        self.assertEqual(pins.read_text(), "package=2\n")

    def test_metadata_only_uses_oci_image_exporter(self):
        """Requesting metadata alone never reports a Docker schema manifest."""
        result, builds = self.run_build(METADATA_FILE=str(self.metadata))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(builds), 3)
        self.assertIn(
            "type=image,push=false,oci-mediatypes=true,rewrite-timestamp=true",
            builds[-1],
        )


class WorkflowTests(unittest.TestCase):
    """Exercise the shell version parser from each release workflow."""

    def test_version_validation_and_release_refs(self):
        """Accept release versions, reject shell syntax, and bind checkout/release tags."""
        for component in ("kms", "gateway", "verifier"):
            workflow = (ROOT / f".github/workflows/{component}-release.yml").read_text()
            parser = textwrap.dedent(
                workflow.split("        run: |\n", 1)[1].split("\n\n", 1)[0]
            )
            self.assertIn("tag_name: ${{ env.RELEASE_TAG }}", workflow)
            self.assertIn("target_commitish: ${{ env.GIT_REV }}", workflow)
            self.assertIn("&& env.RELEASE_TAG || github.sha", workflow)
            for event in ("push", "workflow_dispatch"):
                for version in (
                    "1.0-rc1",
                    "",
                    "bad;echo injected",
                    "bad\nNAME=value",
                    "x" * 129,
                ):
                    with self.subTest(
                        component=component, event=event, version=version
                    ):
                        with tempfile.NamedTemporaryFile() as output:
                            result = subprocess.run(
                                ["bash", "-euc", parser],
                                capture_output=True,
                                text=True,
                                env={
                                    **os.environ,
                                    "GITHUB_EVENT_NAME": event,
                                    "GITHUB_REF": f"refs/tags/{component}-v{version}"
                                    if event == "push"
                                    else "refs/heads/next",
                                    "DISPATCH_VERSION": version,
                                    "GITHUB_ENV": output.name,
                                },
                            )
                            self.assertEqual(
                                result.returncode == 0, version == "1.0-rc1"
                            )
                            if result.returncode == 0:
                                self.assertIn(
                                    f"RELEASE_TAG={component}-v{version}\n",
                                    Path(output.name).read_text(),
                                )


if __name__ == "__main__":
    unittest.main()
