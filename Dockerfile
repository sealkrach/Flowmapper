FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY flowmapper ./flowmapper
RUN pip install --no-cache-dir .
ENV FLOWMAPPER_HOST=0.0.0.0
EXPOSE 8000
CMD ["flowmapper", "serve", "--host", "0.0.0.0", "--port", "8000"]
