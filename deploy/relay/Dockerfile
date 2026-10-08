# The Ascend relay, as an image the CUSTOMER runs inside their own network.
#
# WHY IT HAS TO BE THEIRS. The relay only exists because the target is not reachable from
# Straiker. That single fact settles where it can run: if we could reach the agent from our
# cloud we would call it directly and there would be no relay at all. So a Straiker-hosted relay
# does nothing for the case that needs one. It belongs beside the agent under test, in the
# account that already has a deployment path, a secret store and an audit trail.
# (`ascend-agent/notes/relay-where-it-runs.md` works this through.)
#
# WHAT IT REPLACES. Today the relay is a detached local process supervised by
# `runtime/supervisor.py` on an engineer's laptop. It genuinely survives the CLI exiting and the
# terminal closing — that was verified — but it does not survive the machine: sleep, shutdown,
# VPN drop. The operating workaround is literally `caffeinate -dims &`. A Fargate task, a Cloud
# Run job or a Kubernetes Job has none of those failure modes.
#
# BUILD (from the repository ROOT, not from this directory — the COPY paths below are
# repo-relative because the image needs the CLI, not just this folder):
#
#     docker build -f deploy/relay/Dockerfile -t ascend-relay:1.1.4 .
#
# This build WAS executed, for linux/arm64 and linux/amd64, and both images were run locally. No
# image was ever PUSHED to a registry and nothing was ever pulled from one; see "Never executed"
# in README.md for exactly what that leaves unproven.
# (This comment used to say the build had never run, which stopped being true later in the same
# session. A stale honesty note is worse than none: the next reader trusts it.)

# python:3.12-slim, not 3.13: the repository's CI matrix is ["3.9", "3.12"] and 3.12 is the
# current release it actually runs on. Shipping an image on a version nothing tests would be a
# claim of support rather than a fact. -slim because the runtime is pure HTTP — it needs no
# compiler, and the browser/AWS/GCP adapters pull their dependencies lazily (verified: importing
# `dispatch` registers all 15 adapters with only `requests` installed).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# `requests` is the CLI's one hard dependency (pyproject: requests>=2.32.0, websockets>=12.0).
# `websockets` is imported lazily and only by the `websocket_direct` adapter, so it is installed
# here as well rather than leaving that one adapter to fail at the first probe — a relay that
# dies on probe 1 is the failure mode this whole directory exists to remove.
RUN pip install --no-cache-dir "requests>=2.32.0" "websockets>=12.0"

# EXACTLY the four packages the relay path imports. Measured, not assumed: this set was copied
# into an empty tree on its own and `runtime start` leased 28 probes through it, called the
# target 28 times and delivered 28 results. 52 files, 1.4 MB.
#   shells/    the CLI entrypoint; `runtime start` and the self-reconcile beat live here
#   runtime/   lease_client, dispatch, the 15 adapters, configs, supervisor, tenant
#   control/   api.py — the v3 client the reconcile beat polls for assessment state
#   reporting/ imported at the top of shells/cli/ascend.py (analyze, turns); not optional
# configs/, tests/, docs/, demo/, transport/ and skills/ are deliberately absent: the bundled
# example configs are a read path the container never uses (it is handed its own config through
# the environment), and shipping a customer an image full of other people's examples is noise a
# security review has to read.
WORKDIR /opt/ascend
COPY shells/    /opt/ascend/shells/
COPY runtime/   /opt/ascend/runtime/
COPY control/   /opt/ascend/control/
COPY reporting/ /opt/ascend/reporting/
COPY deploy/relay/entrypoint.py /opt/ascend/relay-entrypoint.py

# Two writable directories, because the relay writes exactly two kinds of file and nothing else:
#   state/  the heartbeat — `<state>/relays/<app_id>.json`, which is how this container knows
#           whether the relay finished its run or died. Its path comes from $ASCEND_STATE_DIR.
#   work/   the target config, materialised 0600 from the environment at startup.
# Owned by the non-root user below so the image still runs under a read-only root filesystem
# with these two mounted as tmpfs/emptyDir — which is how the task definitions in this directory
# run it. $HOME is set because `tenant.py` resolves `~/.ascend`; nothing writes there on this
# path, but an unset HOME makes that expansion land on `/`.
RUN mkdir -p /var/lib/ascend/state /var/lib/ascend/work \
    && useradd --no-create-home --uid 10001 --home-dir /var/lib/ascend --shell /usr/sbin/nologin ascend \
    && chown -R ascend:ascend /var/lib/ascend
ENV ASCEND_STATE_DIR=/var/lib/ascend/state \
    ASCEND_RELAY_WORKDIR=/var/lib/ascend/work \
    ASCEND_CLI=/opt/ascend/shells/cli/ascend.py \
    HOME=/var/lib/ascend

# Non-root, and nothing in the image is a secret. The relay key, the PAT and any credential the
# target needs all arrive as environment variables from the orchestrator's secret store at run
# time — see README.md. Baking one in would put a live customer credential in every layer of
# every registry the image is ever copied to.
USER ascend

# No HEALTHCHECK. A health probe here could only report that the process is alive, and "alive"
# is precisely the state that lies: a relay can be running and leasing nothing. The honest
# signal this image has is its EXIT CODE, which the entrypoint makes mean something (0 only if
# the bound assessment finished AND this relay carried probes for it). Do not add a healthcheck
# that passes while the run is silently unserved.
ENTRYPOINT ["python3", "/opt/ascend/relay-entrypoint.py"]
