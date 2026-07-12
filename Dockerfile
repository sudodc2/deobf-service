# Deobfuscation backend — bundles Node + Python + .NET + Java + Luau so the
# real per-obfuscator tools can run behind one HTTP API.
FROM node:20-bookworm

# ---- system toolchains ------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip ca-certificates curl wget unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# .NET 9 SDK (for the MoonSec deobfuscator)
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 9.0 --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# Luau (for the Moonveil static/trace pipeline)
RUN set -eux; \
    url="https://github.com/luau-lang/luau/releases/latest/download/luau-ubuntu.zip"; \
    wget -q "$url" -O /tmp/luau.zip && unzip -o /tmp/luau.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/luau* && rm /tmp/luau.zip

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# Python deps for Moonveil (Hercules is dependency-free)
RUN pip3 install --no-cache-dir -r tools/moonveil/requirements.txt || true

# Build the MoonSec (.NET) deobfuscator
RUN cd tools/moonsec && dotnet publish -c Release -o bin/Release/net9.0 || \
    echo "WARN: MoonSec build failed; MoonSec deobf will be unavailable"

# unluac (Lua 5.1 bytecode -> source) for the MoonSec pipeline
RUN wget -q "https://sourceforge.net/projects/unluac/files/latest/download" -O tools/unluac.jar || \
    echo "WARN: unluac fetch failed; MoonSec will return bytecode/disasm only"

ENV MOONSEC_BIN=/app/tools/moonsec/bin/Release/net9.0/MoonsecDeobfuscator
ENV UNLUAC_JAR=/app/tools/unluac.jar
ENV PORT=8080
EXPOSE 8080
CMD ["node", "server.js"]
