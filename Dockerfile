# Stage 1 — Build
FROM gradle:8-jdk17 AS build
WORKDIR /app
COPY . .
RUN gradle build -x test --no-daemon

# Stage 2 — Run (slim JRE image)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN apk add --no-cache git maven && \
    addgroup -S vulnhawk && adduser -S vulnhawk -G vulnhawk
COPY --from=build /app/build/libs/*.jar app.jar
RUN chown vulnhawk:vulnhawk app.jar

USER vulnhawk
EXPOSE 8080

ENTRYPOINT ["java", \
  "-Xmx512m", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
