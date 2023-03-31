FROM rust:1.67

#### from https://github.com/hyperledger/sawtooth-core/blob/7651cb5552800dbac98559b46339a84eae472ef7/families/smallbank/smallbank_rust/Dockerfile
RUN apt-get update \
 && apt-get install -y \
 curl \
 gcc \
 libssl-dev \
 libzmq3-dev \
 pkg-config \
 unzip

# For Building Protobufs
RUN curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

ENV PATH=$PATH:/protoc3/bin \
    CARGO_INCREMENTAL=0
### end from https://github.com/hyperledger/sawtooth-core/blob/7651cb5552800dbac98559b46339a84eae472ef7/families/smallbank/smallbank_rust/Dockerfile

WORKDIR /project
COPY Cargo.toml .

RUN cargo fetch

COPY ./src ./src

RUN cargo install --path .

CMD ["target/release/ledger-tp"]
