package se.moln.productservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

@Service
public class JwtService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Lexon "sub" nga JWT (emaili i user-it).
     */
    public String extractUsername(String token) {
        try {
            JsonNode payload = parsePayload(token);
            if (payload != null && payload.has("sub")) {
                return payload.get("sub").asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Kontrollon nëse token ka strukturë të mirë dhe nuk ka skaduar.
     */
    public boolean isTokenValid(String token) {
        try {
            if (token == null || token.isBlank()) {
                return false;
            }

            JsonNode payload = parsePayload(token);
            if (payload == null) {
                return false;
            }

            // Kontrollo exp nëse ekziston (epoch seconds)
            if (payload.has("exp")) {
                long exp = payload.get("exp").asLong();
                long now = Instant.now().getEpochSecond();
                if (exp < now) {
                    return false; // token i skaduar
                }
            }

            // SIGURUHEMI që ka "sub"
            return payload.has("sub") && !payload.get("sub").asText().isBlank();
        } catch (Exception e) {
            return false;
        }
    }


    private JsonNode parsePayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return null;
        }

        String payloadJson = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );

        try {
            return objectMapper.readTree(payloadJson);
        } catch (Exception e) {
            return null;
        }
    }
}
