package dev.alaka.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point of the Alaka gateway.
 *
 * <p>Component scanning starts at the root package {@code dev.alaka} so that all four subsystems
 * ({@code core}, {@code nidhi}, {@code mudra}, {@code yaksha}) are covered, not only this class's
 * own package.
 */
@SpringBootApplication(scanBasePackages = "dev.alaka")
public class AlakaApplication {

    /**
     * Starts the application.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(AlakaApplication.class, args);
    }
}
