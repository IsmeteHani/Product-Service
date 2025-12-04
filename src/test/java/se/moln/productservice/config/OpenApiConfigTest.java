package se.moln.productservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class OpenApiConfigTest {

    @Test
    void productServiceOpenAPI_ShouldConfigureSecurityInfoAndServers() {
        OpenApiConfig cfg = new OpenApiConfig();
        OpenAPI api = cfg.productServiceOpenAPI();

        assertThat(api).isNotNull();
        Components comps = api.getComponents();
        assertThat(comps).isNotNull();
        SecurityScheme scheme = comps.getSecuritySchemes().get("basicAuth");
        assertThat(scheme).isNotNull();
        assertThat(scheme.getType()).isEqualTo(SecurityScheme.Type.HTTP);
        assertThat(scheme.getScheme()).isEqualTo("basic");

        Info info = api.getInfo();
        assertThat(info).isNotNull();
        assertThat(info.getTitle()).isEqualTo("Product Service API");
        assertThat(info.getVersion()).isEqualTo("v1");

        assertThat(api.getServers()).extracting(Server::getUrl)
                .contains(
                        "https://product-service-ismete-c7brajeca5ajbqgk.northeurope-01.azurewebsites.net",
                        "http://localhost:8081"
                );
    }
}