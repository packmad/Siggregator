FROM debian:bullseye-slim

ARG DIE_VERSION="3.01"

RUN apt update && apt install --no-install-recommends -y wget git automake libtool make gcc pkg-config libmagic-dev \
    tar libglib2.0-0 python3 python3-dev python3-pip && pip install --upgrade pip && \
    # yara-python
    git clone --recursive https://github.com/VirusTotal/yara-python.git && cd yara-python && \
    python3.9 setup.py build --enable-macho --enable-dotnet --enable-magic && python3.9 setup.py install && \
    rm -rf yara-python && \
    # die
    wget "https://github.com/horsicq/DIE-engine/releases/download/$DIE_VERSION/die_lin64_portable_$DIE_VERSION.tar.gz" && \
    tar -xzf "die_lin64_portable_$DIE_VERSION.tar.gz" && rm -rf /die_lin64_portable/base/db && \
    # die db update
    git clone https://github.com/horsicq/Detect-It-Easy.git && mv Detect-It-Easy/db/ /die_lin64_portable/base/ && \
    rm -rf Detect-It-Easy/

COPY requirements.txt .
RUN python3.9 -m pip install --no-cache-dir -r /requirements.txt

COPY siggregator/ siggregator/
WORKDIR siggregator

# generate signatures ; ignore errors
RUN python3.9 main.py; exit 0

ENTRYPOINT ["python3.9", "main.py", "/bin"]
#ENTRYPOINT ["yes"]