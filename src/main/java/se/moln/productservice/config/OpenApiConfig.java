package se.moln.productservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI productServiceOpenAPI() {
        final String BASIC_SCHEME = "basicAuth";

        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(BASIC_SCHEME,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("basic")
                                        .description("Login with username/password to call admin endpoints")
                        )
                )
                .info(new Info()
                        .title("Product Service API")
                        .version("v1")
                        .description("Product endpoints")
                )
                .servers(List.of(
                        new Server()
                                .url("https://product-service-ismete-c7brajeca5ajbqgk.northeurope-01.azurewebsites.net")
                                .description("Production server (Azure)"),
                        new Server()
                                .url("http://localhost:8082")
                                .description("Local development server")
                ));
    }
}