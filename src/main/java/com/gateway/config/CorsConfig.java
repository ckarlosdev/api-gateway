package com.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {
    @Bean
    public CorsWebFilter corsWebFilter() {
        // 1. Crear la fuente de configuración de CORS
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        // 2. Configurar orígenes permitidos
        // Permitir el origen de desarrollo de tu frontend de React
        // ¡Importante! En producción, cambia esto al dominio real (ej: https://tudominio.com)
        config.setAllowedOrigins(List.of("http://localhost:5173", "http://127.0.0.1:5173", "https://oleo-soft.com", "https://ckarlosdev.github.io"));

        // 3. Configurar métodos y encabezados
        // Permitir todos los métodos HTTP que vas a usar (POST, GET, OPTIONS, etc.)
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        // Permitir todos los headers, incluyendo 'Authorization' (para el JWT)
        config.setAllowedHeaders(List.of("*"));

        // 4. Permitir credenciales (importante para enviar cookies/tokens de autenticación)
        config.setAllowCredentials(true);

        // 5. Aplicar esta configuración a todas las rutas (/**)
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}
