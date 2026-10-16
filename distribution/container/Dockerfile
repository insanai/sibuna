# The static musl executable on a distroless base: CA certificates and an unprivileged
# identity, but no shell, package manager or download tools. The base is pinned by digest.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG TARGETARCH
COPY --chmod=0555 linux-${TARGETARCH}/sibuna /usr/local/bin/sibuna
COPY linux-${TARGETARCH}/LICENSE linux-${TARGETARCH}/NOTICE linux-${TARGETARCH}/README.md linux-${TARGETARCH}/SECURITY.md linux-${TARGETARCH}/sibuna.build.json /usr/share/doc/sibuna/
COPY linux-${TARGETARCH}/LICENSES/ /usr/share/doc/sibuna/LICENSES/
COPY --chown=65532:65532 --chmod=0700 state/ /var/lib/sibuna/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sibuna"]
