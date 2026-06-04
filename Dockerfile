FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        clang \
        make \
        cmake \
        valgrind \
        python3 \
        python3-venv \
        git \
        vim \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Pin upper bounds too: pydantic in particular has been willing to break
# `@model_validator` semantics across 2.x minor releases, and we want a
# Dockerfile rebuild months from now to keep working without surprise. If
# you bump a major, run the full test suite first.
#
# `rich` is listed explicitly because typer only depends on it transitively
# today, which would break us if typer ever made it optional.
RUN pip install --no-cache-dir \
        "typer>=0.12,<1.0" \
        "pydantic>=2,<3" \
        "pyyaml>=6,<7" \
        "jinja2>=3,<4" \
        "rich>=13,<15" \
        "pytest>=8,<9"

WORKDIR /workspace

CMD ["/bin/bash"]
