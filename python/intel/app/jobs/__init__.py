"""mark1-intel's job registry (06 §7.2 schedules); importing this never imports a lane."""

from app.jobs.registry import Job

JOBS: tuple[Job, ...] = (
    Job("tvo.rollup_verify", "app.tvo.jobs:rollup_verify", "hourly"),
    Job("memory.extract", "app.memory.jobs:extract", "nightly"),
    Job("memory.admit", "app.memory.jobs:admit", "nightly", ("memory.extract",)),
    Job(
        "policy_compiler.compile", "app.policy_compiler.jobs:compile", "nightly", ("memory.admit",)
    ),
    Job("ope.score", "app.ope.jobs:score", "nightly"),
    Job("corpus.export", "app.corpus.jobs:export", "nightly"),
    Job("rm.contributions", "app.corpus.contributions:export", "nightly"),
    Job("digest.weekly", "app.digest.weekly:weekly", "weekly"),
)
