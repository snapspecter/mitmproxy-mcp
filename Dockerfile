# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set the working directory to /app
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy the project configuration files
COPY pyproject.toml README.md /app/
# Copy the lockfile if it exists (it might not yet)
COPY uv.lock* /app/

# Install the project's dependencies
# --no-dev: defaults to production deps
# --no-install-project: we install the project in the next step
RUN uv sync --no-dev --no-install-project

# Copy the rest of the source code
COPY . /app

# Install the project itself
RUN uv sync --no-dev

# Place the virtual environment executables in the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Expose the default port
EXPOSE 8080

# Run the application
CMD ["mitmproxy-mcp"]
