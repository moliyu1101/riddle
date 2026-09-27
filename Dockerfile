# ===== 阶段 1：构建 Vue 前端 =====
FROM node:20-slim AS frontend
WORKDIR /fe
# npm ci 严格按 package-lock.json 安装：构建可复现，不随上游 minor/patch 浮动
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build
# 产物在 /fe/../web/dist → /web/dist

# ===== 阶段 2：Python 应用 + 全套安全工具 =====
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 国内网络下 deb.debian.org 经常无法解析/断流；切清华镜像后 apt 才能解析并装包。
# python:3.12-slim 用 deb822(includes) 源文件，也存在 /etc/apt/sources.list。
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list

# 系统工具 + 挖洞常用工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        python3-pip \
        jq dnsutils iputils-ping netcat-openbsd \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

# sqlmap：官方 PyPI 月度版。构建不依赖 git clone GitHub（国内常超时/失败），
# 也比跟踪 master HEAD 稳。pip 会把 sqlmap 装到 PATH，无需再包一层 wrapper。
# 清华镜像走正规 HTTPS 证书，不加 --trusted-host（那会关闭证书校验、引入投毒面）。
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple sqlmap

# ProjectDiscovery 工具：nuclei + httpx（从官方 release 拉二进制，避免装 Go）
# 国内构建优先 ghfast / ghproxy，失败再直连 GitHub。zip 无效则失败，避免镜像 silently 缺工具。
# 供应链：zip 经第三方代理下载，必须与官方 checksums.txt 比对 sha256 才落地
# （checksums 优先直连 GitHub 拉取，与 zip 的代理源分离；拉不到 checksums 直接构建失败）。
# TARGETARCH 由 buildkit 自动注入(arm64/amd64)
ARG TARGETARCH
RUN set -eux; \
    NUCLEI_VER=3.3.7; HTTPX_VER=1.6.9; \
    cd /tmp; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    fetch_checksums() { \
      dest="$1"; shift; \
      for u in "$@"; do \
        echo "GET $u"; \
        if wget -q -T 45 -O "$dest" "$u"; then return 0; fi; \
        rm -f "$dest"; \
      done; \
      echo "ERROR: could not download checksums $dest — refusing to install unverified binaries" >&2; \
      return 1; \
    }; \
    fetch_zip() { \
      dest="$1"; zipname="$2"; sums="$3"; shift 3; \
      for u in "$@"; do \
        echo "GET $u"; \
        if wget -q -T 45 -O "$dest" "$u" && unzip -tq "$dest" >/dev/null 2>&1; then \
          want=$(grep " ${zipname}\$" "$sums" | awk '{print $1}'); \
          if [ -z "$want" ]; then echo "ERROR: $zipname not in checksums" >&2; return 1; fi; \
          echo "$want  $dest" | sha256sum -c - >/dev/null 2>&1 || { \
            echo "ERROR: sha256 MISMATCH for $zipname (source $u)" >&2; rm -f "$dest"; continue; \
          }; \
          return 0; \
        fi; \
        rm -f "$dest"; \
      done; \
      echo "ERROR: could not download valid $dest" >&2; \
      return 1; \
    }; \
    fetch_checksums nuclei_checksums.txt \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_checksums.txt" \
      "https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_checksums.txt"; \
    fetch_checksums httpx_checksums.txt \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_checksums.txt" \
      "https://ghfast.top/https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_checksums.txt"; \
    fetch_zip nuclei.zip "nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" nuclei_checksums.txt \
      "https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" \
      "https://ghproxy.net/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip"; \
    fetch_zip httpx.zip "httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" httpx_checksums.txt \
      "https://ghfast.top/https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" \
      "https://ghproxy.net/https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip"; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin/; \
    unzip -o httpx.zip httpx -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx; \
    rm -f /tmp/*.zip; \
    apt-get purge -y unzip; rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# 国内网络优先清华 PyPI 镜像，提速并降低 install 失败率（HTTPS 证书正规，无需 trusted-host）
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 真实浏览器截图：playwright + chromium（无头）。--with-deps 自动装系统依赖；
# 国内网络下载失败不阻断构建，但必须打出显著警告——截图功能缺失时
# capture_evidence 会返回明确提示。浏览器装到共享目录：容器最终以非 root 用户运行，
# 默认 $HOME 安装会导致降权后找不到 chromium，这里用 PLAYWRIGHT_BROWSERS_PATH 固定位置（world-readable）。
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN python -m playwright install --with-deps chromium || echo "WARN: playwright chromium 安装失败，截图功能将不可用（capture_evidence 会提示）" >&2

# 应用运行用户：先建好，下面 nuclei 模板直接装到其 HOME，
# 否则运行期降权后 nuclei 找不到模板（模板只在 /root 下）。
RUN useradd --create-home --uid 10001 riddle

# 更新 nuclei 模板到 riddle HOME（失败不阻断构建，但打警告——无模板时 verify_known_vuln 不可用）
RUN su riddle -s /bin/sh -c "HOME=/home/riddle nuclei -update-templates -silent" || echo "WARN: nuclei 模板更新失败，已知漏洞验证工具将不可用" >&2

COPY . .
# Windows 检出/解压可能带 CRLF；入口脚本带 \r 时容器会报 no such file or directory，
# 带 UTF-8 BOM 时 shebang 行会被 sh 当命令报 not found。两者都清掉（防御未来）。
RUN find /app/scripts -type f -name '*.sh' -exec sed -i '1s/^\xEF\xBB\xBF//;s/\r$//' {} +

# 拷入前端构建产物（覆盖空的 web/dist）
COPY --from=frontend /web/dist /app/web/dist

# 工作区 + 数据目录（数据目录建议挂卷持久化）
RUN mkdir -p /work /app/data
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/riddle.db

# 降权运行：应用进程非 root——即使 LLM 被诱导执行破坏性命令，OS 权限层兜底
# （无法删 /app 代码、/etc 配置、/root 家目录；仅 /app/data 与 /work 可写）。
# 注意：update API 的 git pull/pip 需要写 /app 与系统 site-packages，降权后
# 一键更新会失败并干净报错；需要更新请用 docker compose up -d --build。
RUN chown -R riddle:riddle /work /app/data
USER riddle

EXPOSE 18800

CMD ["sh", "/app/scripts/run-with-watchdog.sh"]
