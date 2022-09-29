FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install --no-install-recommends -y wget git automake libtool make cmake gcc g++ pkg-config libmagic-dev \
    tar unzip libglib2.0-0 libssl-dev libfuzzy-dev python3.9 python3.9-dev python3-pip \
    # die dependencies
    qtbase5-dev qtscript5-dev qttools5-dev-tools build-essential qt5-default libqt5svg5 libqt5opengl5 && \ 
    pip install --upgrade pip && \
    # yara-python
    git clone --recursive https://github.com/VirusTotal/yara-python.git && cd yara-python && \
    python3.9 setup.py build --enable-macho --enable-dotnet --enable-magic && python3.9 setup.py install && \
    rm -rf /yara-python

# protobuf
RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v2.5.0/protobuf-2.5.0.tar.gz && \
    tar -xzf protobuf-2.5.0.tar.gz && rm protobuf-2.5.0.tar.gz && \
    cd protobuf-2.5.0 && ./configure && make && make install && ldconfig && cd .. && rm -rf protobuf-2.5.0/ && \
    # sdhash
    git clone https://github.com/sdhash/sdhash.git && cd sdhash && make && make install && cd .. && rm -rf sdhash/

# die
ENV DIE_VER 3.06
RUN wget https://github.com/horsicq/DIE-engine/releases/download/${DIE_VER}/die_${DIE_VER}_Ubuntu_20.04_amd64.deb && \
    dpkg -i die_${DIE_VER}_Ubuntu_20.04_amd64.deb && rm die_${DIE_VER}_Ubuntu_20.04_amd64.deb

COPY requirements.txt .
RUN python3.9 -m pip install --no-cache-dir -r /requirements.txt

COPY siggregator/ siggregator/
WORKDIR siggregator

# generate signatures
RUN python3.9 siggregator.py 2>/dev/null; exit 0

ENTRYPOINT ["python3.9", "siggregator.py"]
