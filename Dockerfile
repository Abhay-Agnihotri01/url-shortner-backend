FROM openjdk:17-slim

WORKDIR /app

COPY target/url-shortener-sb-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

CMD ["java", "-Dspring.profiles.active=prod", "-jar", "app.jar"]
