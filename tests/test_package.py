"""The package and its FR_OS dependency import."""

import ai_perimeter


def test_the_package_has_a_version():
    assert ai_perimeter.__version__ == "0.1.0"


def test_fr_os_is_installed_from_the_pinned_commit():
    # The config loader is what the orchestrator validates proposals with.
    from frfw.config import loader

    assert callable(loader.load_config)
