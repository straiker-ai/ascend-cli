# The adapter shim, built FROM THE HAND-OVER BUNDLE FOLDER (adapter.json, vendor/, shim/ beside each other):
#   docker build -f shim/Dockerfile -t ascend-shim .
#   docker run -p 8787:8787 --env-file secrets.env -e SHIM_KEY=… ascend-shim
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir "requests>=2.32.0" "websockets>=12.0"
WORKDIR /opt/bundle
COPY vendor/ /opt/bundle/vendor/
COPY shim/ /opt/bundle/shim/
COPY adapter.json /opt/bundle/adapter.json
ENV ADAPTER_CONFIG=/opt/bundle/adapter.json PORT=8787
EXPOSE 8787
CMD ["python3", "/opt/bundle/shim/app.py"]
