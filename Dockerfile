# Use a Python image with uv pre-installed, pinned to a digest so the base
# cannot change under us between builds.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58

# Set the working directory to /app
WORKDIR /app

# Enable bytecode compilation and bytecode-only installs.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1

# Copy the project configuration files
COPY pyproject.toml README.md /app/
# Copy the lockfile if it exists (it might not yet)
COPY uv.lock* /app/

# Install the project's dependencies
# --no-dev: defaults to production deps
# --no-install-project: we install the project in the next step
RUN uv sync --frozen --no-dev --no-install-project

# Copy the rest of the source code
COPY . /app

# Install the project itself
RUN uv sync --frozen --no-dev

# Place the virtual environment executables in the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Run as a non-root user. The proxy binds loopback by default; publishing a
# port is an explicit operator decision (see docker-compose.yml).
RUN groupadd --system app && useradd --system --gid app --create-home app \
    && chown -R app:app /app
USER app

# Expose the default port
EXPOSE 8080

# Run the application
CMD ["mitmproxy-mcp"]
