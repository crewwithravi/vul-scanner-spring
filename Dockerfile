# Stage 1 — Build
FROM gradle:8-jdk17 AS build
WORKDIR /app
COPY . .
RUN gradle build -x test --no-daemon

# Stage 2 — Run (slim JRE image)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN apk add --no-cache git maven su-exec && \
    addgroup -S vulnhawk && adduser -S vulnhawk -G vulnhawk && \
    mkdir -p /home/vulnhawk/.gradle /home/vulnhawk/.m2

COPY --from=build /app/build/libs/*.jar app.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown vulnhawk:vulnhawk app.jar

EXPOSE 9090

# Entrypoint runs as root briefly to fix volume ownership, then su-exec to vulnhawk
ENTRYPOINT ["/entrypoint.sh"]
