# ─── Stage 1: Build ───────────────────────────────────────────────────────
FROM maven:3.9.11-eclipse-temurin-21 AS builder

WORKDIR /build

COPY pom.xml .
COPY checkstyle ./checkstyle
COPY src ./src

RUN mvn clean package -DskipTests -Dcheckstyle.skip
# ─── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine

RUN addgroup -S sondhan && adduser -S sondhan -G sondhan

WORKDIR /app

COPY --from=builder /build/target/sondhan-auth-service-*.jar app.jar

RUN chown sondhan:sondhan app.jar

USER sondhan

EXPOSE 8086

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
