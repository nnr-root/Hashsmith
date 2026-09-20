# Hashsmith — encoding, decoding, hashing, cracking.
#
# The default build is pure Go with CGO_ENABLED=0, so the runtime stage needs
# no libc, no Go toolchain and no GPU runtime. That is the whole distribution
# promise of this project, and this image is the cheapest way to demonstrate
# it: the result is one static binary in a scratch image.
#
#   docker build -t hashsmith .
#   docker run --rm hashsmith --version
#   docker run --rm hashsmith -N identify 5f4dcc3b5aa765d61d8327deb882cf99
#   docker run --rm -v "$PWD:/work" -w /work hashsmith crack -t md5 -w rockyou.txt hashes.txt
#
# GPU support is deliberately absent. It needs cgo plus a vendor runtime inside
# the container, which is a different image with a different promise; see
# `hashsmith gpu` for what an opt-in build provides.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY hashsmith/go_hashsmith/go.mod hashsmith/go_hashsmith/go.sum ./
RUN go mod download

COPY hashsmith/go_hashsmith/ ./

# VERSION is stamped in so the image can say what it is. Without it the binary
# reports "dev", which is not something you want on a client engagement.
ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_DATE=""
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/hashsmith ./cmd/hashsmith

# Fail the build rather than ship a binary whose own vectors do not pass.
RUN /out/hashsmith -N selftest >/dev/null

FROM scratch
COPY --from=build /out/hashsmith /hashsmith

# /work is where the caller mounts their hashes and wordlists, and HOME points
# at it deliberately: Hashsmith keeps its potfile and resumable sessions under
# $HOME/.hashsmith, and a scratch image has no home directory at all. Without
# this the tool still cracks, but every run starts with an empty potfile and
# --session silently has nowhere to write. Mounting a volume at /work therefore
# preserves both.
WORKDIR /work
ENV HOME=/work

ENTRYPOINT ["/hashsmith"]
CMD ["--help"]
