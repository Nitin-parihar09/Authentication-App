FROM ubuntu:latest AS build

RUN apt-get update

RUN apt-get install openjdk-17-jdk -y

FROM maven:latest AS build

WORKDIR /app

COPY . .

RUN mvn clean package

FROM openjdk:17-jdk-slim

EXPOSE 8080

COPY --from=build /spring-boot-spring-security-jwt-authentication/target/spring-boot-spring-security-jwt-authentication.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
