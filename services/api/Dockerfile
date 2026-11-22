FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system apkinspector && useradd --system --gid apkinspector apkinspector

WORKDIR /app
COPY pyproject.toml README.md* ./
COPY app ./app
RUN pip install --upgrade pip && pip install .

USER apkinspector
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]

FROM runtime AS test
USER root
COPY tests ./tests
RUN pip install ".[dev]"
CMD ["pytest"]
