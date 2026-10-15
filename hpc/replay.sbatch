#!/bin/bash -l
#SBATCH --job-name=aegis-replay
#SBATCH --account=aai6610.202610
#SBATCH --partition=short
#SBATCH --cpus-per-task=4
#SBATCH --mem=12G
#SBATCH --time=02:00:00
#SBATCH --output=/scratch/%u/aegis-sec/logs/%x-%j.out
# Starts the pinned Elasticsearch for this job only (loopback, job-scoped data dir), replays every
# supported Sigma rule against the regression and OTRF pools, then stops the engine and deletes its
# data. Run hpc/acquire.sh and hpc/fetch_engine.sh first.
# The engine has security disabled and listens on 127.0.0.1 of a shared compute node. It holds only
# public benchmark data and lives only for this job.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" UV_OFFLINE=1
DATA="/scratch/$USER/aegis-sec/data"
ES_HOME="/scratch/$USER/aegis-sec/engine/elasticsearch-8.19.3"
PORT=$((19200 + SLURM_JOB_ID % 700))
RUN=$(mktemp -d "/scratch/$USER/aegis-sec/engine/run-$SLURM_JOB_ID-XXXX")
cleanup() {
  [ -f "$RUN/pid" ] && kill "$(cat "$RUN/pid")" 2>/dev/null && sleep 5
  rm -rf "$RUN"
}
trap cleanup EXIT
ES_JAVA_OPTS="-Xms4g -Xmx4g" "$ES_HOME/bin/elasticsearch" -d -p "$RUN/pid" \
  -E path.data="$RUN/data" -E path.logs="$RUN/logs" \
  -E discovery.type=single-node -E network.host=127.0.0.1 -E http.port="$PORT" \
  -E xpack.security.enabled=false -E xpack.ml.enabled=false -E cluster.name="aegis-$SLURM_JOB_ID"
for _ in $(seq 1 90); do
  curl -fs "http://127.0.0.1:$PORT/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null && break
  sleep 2
done
curl -fs "http://127.0.0.1:$PORT/" | grep '"number"'
uv run --no-sync python -m aegisbench replay --root "$DATA" --es-url "http://127.0.0.1:$PORT"
