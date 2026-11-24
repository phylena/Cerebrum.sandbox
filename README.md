# Cerebrum.sandbox

Self-hosted isolated execution infrastructure for [Cerebrum.model](https://github.com/CerveauAnalytique/Cerebrum.model).
Cerebrum stays the brain; this service only runs what Cerebrum asks, inside sandboxes.

**Status: early (phases 1-5 foundation).** See [docs/architecture.md](docs/architecture.md) for what is
implemented, what is verified, and the roadmap. The Docker adapter has **not** been verified against a live
daemon yet, so do not treat it as production-ready.

```bash
pip install -e '.[test]' && python -m pytest        # unit tests (no Docker needed)
cp .env.example .env                                # set keys, then export them
docker build -t cerebrum-sandbox/base:latest -f images/base.Dockerfile images
python -m cerebrum_sandbox                          # API on 127.0.0.1:8300, docs at /docs
pytest -m docker                                    # live isolation tests (needs the daemon + image)
```

```bash
K="Authorization: Bearer $SANDBOX_OPERATOR_KEY"
curl -sX POST localhost:8300/api/v1/sandboxes -H "$K" -H content-type:application/json -d '{"profile":"basic"}'
curl -sX POST localhost:8300/api/v1/sandboxes/<id>/execute -H "$K" -H content-type:application/json \
     -d '{"argv":["python3","-c","print(1+1)"]}'
```
