FROM python:3.10-slim-bullseye as base

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR=false
ENV POETRY_VERSION 1.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/* \

# FIXME added to skip error on setuptools BEEPRO-3426
ENV SETUPTOOLS_USE_DISTUTILS=stdlib

# COPY Files
WORKDIR /opt/beefree_clients
COPY poetry.lock pyproject.toml ./

#Install dependencies
RUN pip install -U --no-cache-dir pip setuptools==60.10.0
RUN pip install "poetry==$POETRY_VERSION"

RUN poetry install --only main

ARG git_version
ENV git_version ${git_version}
ARG git_tag
ENV git_tag ${git_tag}
ARG git_sha
ENV git_sha ${git_sha}


FROM base as test
RUN poetry install --no-root
COPY . /opt/beefree_clients
RUN poetry install
ENV DJANGO_DOT_ENV_PATH=.envs/test
ENV DJANGO_READ_DOT_ENV_FILE=1

CMD poetry run pytest --reverse -n auto --dist loadscope \
    --cov=beefree_clients \
    --junitxml=tests_reports/junit/junit.xml \ 
    --html=tests_reports/pytest/report.html \
    && poetry run coverage html \
    && cp -r htmlcov tests_reports/ \
    && poetry run coverage xml -o tests_reports/cov.xml \
    && chown -R ${USER_ID}:${GROUP_ID} tests_reports
