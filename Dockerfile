FROM python:3.12-slim

WORKDIR /app
# NOTICE is the authoritative license map and LICENSE-COMMERCIAL carries the
# BUSL-1.1 terms, so an image that ships the commercial modules without them
# distributes the code without its license. `pip install -e .` also reads
# `license-files`, so omitting them breaks the build.
COPY pyproject.toml README.md LICENSE LICENSE-COMMERCIAL NOTICE ./
COPY axon ./axon
RUN pip install --no-cache-dir -e .

WORKDIR /work
ENTRYPOINT ["axon"]
CMD ["--help"]
