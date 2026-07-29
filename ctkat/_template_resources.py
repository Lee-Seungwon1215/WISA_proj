"""Load bundled Jinja templates through :mod:`importlib.resources`.

The project used to point Jinja at ``Path(__file__).parent / "templates"``.
That happened to work in a source checkout, but the templates were omitted
from built wheels, so an installed CLI failed at its first render.  Keeping
resource access in one module gives both harness generators the same
source/install behavior and makes the package-data contract testable.
"""

from importlib import resources
from typing import Collection

from jinja2 import DictLoader, Environment, StrictUndefined


def read_template(name: str) -> str:
    """Return one bundled template as UTF-8 text.

    ``name`` is always selected from a code-owned allowlist before reaching
    this helper.  The basename check is defense in depth against accidentally
    turning this into a package-resource traversal primitive later.
    """

    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError(f"template name must be a basename, got {name!r}")
    resource = resources.files("ctkat").joinpath("templates").joinpath(name)
    return resource.read_text(encoding="utf-8")


def make_environment(template_names: Collection[str]) -> Environment:
    """Build a strict Jinja environment from installed package resources."""

    loader = DictLoader({name: read_template(name) for name in template_names})
    return Environment(
        loader=loader,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
