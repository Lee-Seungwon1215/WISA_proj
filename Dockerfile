FROM ubuntu:24.04 AS base

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

COPY pyproject.toml README.md LICENSE /opt/ctkat-src/
COPY ctkat /opt/ctkat-src/ctkat
RUN pip install --no-cache-dir --no-deps /opt/ctkat-src \
    && rm -rf /opt/ctkat-src

WORKDIR /workspace

CMD ["/bin/bash"]

# KyberSlash's operand-attribution backend is intentionally opt-in. The
# ordinary runtime above keeps distro Valgrind; this builder pins the exact
# release and full patch published with the IACR artifact.
FROM ubuntu:24.04 AS timecop-builder

ARG VALGRIND_VERSION=3.22.0
ARG VALGRIND_SHA256=c811db5add2c5f729944caf47c4e7a65dcaabb9461e472b578765dd7bf6d2d4c

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        patch \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl --fail --location --silent --show-error \
        "https://sourceware.org/pub/valgrind/valgrind-${VALGRIND_VERSION}.tar.bz2" \
        --output "valgrind-${VALGRIND_VERSION}.tar.bz2"
RUN echo "${VALGRIND_SHA256}  valgrind-${VALGRIND_VERSION}.tar.bz2" | sha256sum --check -
RUN tar -xjf "valgrind-${VALGRIND_VERSION}.tar.bz2"

COPY ctkat/_vendor/kyberslash_timecop/valgrind-3.22.0-varlat.patch /build/
RUN patch --directory="/build/valgrind-${VALGRIND_VERSION}" --strip=1 \
        < /build/valgrind-3.22.0-varlat.patch
RUN cd "/build/valgrind-${VALGRIND_VERSION}" \
    && ./configure --prefix=/opt/ctkat-timecop --enable-only64bit
RUN make --directory="/build/valgrind-${VALGRIND_VERSION}" -j2
RUN make --directory="/build/valgrind-${VALGRIND_VERSION}" install

FROM base AS timecop

COPY --from=timecop-builder /opt/ctkat-timecop /opt/ctkat-timecop
ENV CTKAT_TIMECOP_PREFIX=/opt/ctkat-timecop
ENV PATH="/opt/ctkat-timecop/bin:$PATH"
ENV CPATH="/opt/ctkat-timecop/include"

RUN test "$(valgrind --version)" = "valgrind-3.22.0" \
    && grep -q VALGRIND_ENABLE_TIMECOP_MODE \
        /opt/ctkat-timecop/include/valgrind/memcheck.h

FROM base AS runtime
