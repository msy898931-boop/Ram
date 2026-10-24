FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY axon ./axon
RUN pip install --no-cache-dir -e .

WORKDIR /work
ENTRYPOINT ["axon"]
CMD ["--help"]
