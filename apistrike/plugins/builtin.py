"""Built-in APIStrike module specs.

Each spec wraps an existing module class with a ``build()`` factory so it can be
run through the generic ``run-module`` command and the plugin registry, with no
change to the module's behavior. The concrete module class is imported lazily
inside the factory so importing this file stays cheap and dependency-free.

To expose another built-in module, copy the ``misconfig`` block below and map
the :class:`ModuleContext` onto that module's constructor. Nothing else needs
to change.
"""
from __future__ import annotations

from apistrike.plugins import ModuleContext, ModuleSpec, register


def _build_misconfig(ctx: ModuleContext):
    from apistrike.modules.misconfig import ALL_CHECKS, MisconfigModule

    checks_opt = ctx.opt("checks")
    checks = (
        tuple(c.strip() for c in checks_opt.split(",") if c.strip())
        if checks_opt
        else ALL_CHECKS
    )
    return MisconfigModule(
        ctx.client,
        base_url=ctx.base_url,
        probe_paths=[ctx.path],
        evil_origin=ctx.opt("evil_origin", "https://evil.attacker.test"),
        checks=checks,
        headers=ctx.headers,
        safe=ctx.safe,
    )


register(
    ModuleSpec(
        name="misconfig",
        build=_build_misconfig,
        owasp_id="API8:2023",
        description=(
            "Security misconfiguration: missing headers, permissive CORS, "
            "verbose errors, HTTP TRACE, and version banners."
        ),
    )
)
