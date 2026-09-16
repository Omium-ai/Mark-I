"""adjudicator-svc's nightly cascade (06 §1.2, §5): gold.refresh and spectral.estimate are
independent; certs.recompute and readjudicate.run follow spectral.estimate; promotion.step
measures readjudicate's shadow pairs last."""

from app.jobs.registry import Job

JOBS: tuple[Job, ...] = (
    Job("gold.refresh", "app.jobs.nightly:gold_refresh", "nightly"),
    Job("spectral.estimate", "app.jobs.nightly:spectral_estimate", "nightly"),
    Job(
        "certs.recompute",
        "app.jobs.nightly:certs_recompute",
        "nightly",
        ("gold.refresh", "spectral.estimate"),
    ),
    Job("readjudicate.run", "app.jobs.readjudicate:run", "nightly", ("spectral.estimate",)),
    Job(
        "promotion.step",
        "app.jobs.nightly:promotion_step",
        "nightly",
        ("certs.recompute", "readjudicate.run"),
    ),
)
