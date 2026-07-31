from pathlib import Path

import yaml


ROOT = Path(__file__).parent.parent


def test_image_does_not_declare_volumes():
    dockerfile = (ROOT / "Dockerfile").read_text().splitlines()
    volume_instructions = [
        line for line in dockerfile if line.lstrip().startswith("VOLUME ")
    ]

    assert not volume_instructions, (
        "Dockerfile VOLUME instructions create anonymous volumes when a "
        "container does not override the mount"
    )


def test_compose_mounts_are_explicit():
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())
    declared_volumes = set(compose.get("volumes", {}))

    for volume_name, config in compose.get("volumes", {}).items():
        assert config and config.get("name"), (
            f"Top-level volume {volume_name!r} must have an explicit Docker name"
        )

    for service_name, service in compose.get("services", {}).items():
        for mount in service.get("volumes", []):
            if isinstance(mount, str):
                source, separator, _target = mount.partition(":")
                assert separator and source, (
                    f"Service {service_name!r} has an anonymous mount: {mount!r}"
                )
                if not source.startswith((".", "/")):
                    assert source in declared_volumes, (
                        f"Service {service_name!r} uses undeclared volume {source!r}"
                    )
                continue

            mount_type = mount.get("type", "volume")
            source = mount.get("source")
            assert source, f"Service {service_name!r} has an anonymous mount: {mount!r}"
            if mount_type == "volume":
                assert source in declared_volumes, (
                    f"Service {service_name!r} uses undeclared volume {source!r}"
                )
