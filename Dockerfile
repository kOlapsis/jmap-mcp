# Release image, built by GoReleaser from the prebuilt binaries (see Dockerfile.source to build from source).
FROM --platform=$BUILDPLATFORM busybox:1.37 AS dirs
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
LABEL io.modelcontextprotocol.server.name="io.github.kOlapsis/jmap-mcp"
COPY --from=dirs --chown=65532:65532 /data /data
COPY $TARGETPLATFORM/jmap-mcp /jmap-mcp
ENV JMAP_MCP_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s CMD ["/jmap-mcp", "healthcheck"]
ENTRYPOINT ["/jmap-mcp"]
CMD ["serve"]
