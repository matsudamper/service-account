# ネイティブバイナリは事前に ./gradlew :server:nativeCompile で作っておく

# distroless では mkdir できないので、書き込み先のディレクトリだけ別のイメージで作る
FROM busybox:stable AS data
RUN mkdir -p /app/data

FROM gcr.io/distroless/cc-debian13:nonroot
WORKDIR /app

ENV SERVICE_ACCOUNT_DATABASE_PATH=/app/data/service-account.db
EXPOSE 8080 50051

COPY --from=data --chown=nonroot:nonroot /app/data /app/data
# libmanagement_ext.so は native image が実行ファイルの隣から読む
COPY server/build/native/nativeCompile/service-account server/build/native/nativeCompile/libmanagement_ext.so /app/

VOLUME ["/app/data"]
ENTRYPOINT ["/app/service-account"]
CMD ["serve"]
