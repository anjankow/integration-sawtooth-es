FROM hyperledger/sawtooth-shell:chime

RUN cp -a /etc/sawtooth/cli.toml.example /etc/sawtooth/cli.toml && \
    echo 'url = "http://rest-api:8008"' | tee -a /etc/sawtooth/cli.toml

RUN sawtooth keygen
ENTRYPOINT ["tail", "-f", "/dev/null"]
