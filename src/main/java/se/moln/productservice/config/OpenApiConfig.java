package se.moln.productservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI productServiceOpenAPI() {
        final String BEARER_SCHEME = "bearerAuth";

        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(BEARER_SCHEME,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT Bearer token from UserService")
                        )
                )
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME))
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
                                .url("http://localhost:8081")
                                .description("Local development server")
                ));
    }
}
