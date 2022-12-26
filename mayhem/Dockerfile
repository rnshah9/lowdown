FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo
RUN ./configure 
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_rcsdate2str.cpp -fsanitize=fuzzer,address /repo/liblowdown.a -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/lowdown /
COPY --from=builder /fuzz /fuzz_rcsdate2str
