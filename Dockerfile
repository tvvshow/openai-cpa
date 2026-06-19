FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# 纯 Python auth_core 分支：必须保留 utils/auth_core/*.py（这就是核心实现），
# 仅清理回滚用的二进制 .bak（.dockerignore 的 *.pyd 不匹配 .bak 后缀）
RUN rm -f utils/auth_core.*.bak 2>/dev/null || true

EXPOSE 8000
ENV PYTHONUNBUFFERED=1

CMD ["python", "wfxl_openai_regst.py"]