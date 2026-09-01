package com.iam.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IamSystemIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String userAccessToken;
    private static String m2mAccessToken;
    private static String createdUserId;

    @Test
    @Order(1)
    void testJwksEndpoint() throws Exception{
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray());
    }

    @Test
    @Order(2)
    void testHumanLogin() throws Exception{
        Map<String, String> loginRequest = Map.of(
                "userName", "testuser",
                "password", "password123"
        );
        MvcResult result = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andReturn();

        //Extract token for later tests if needed
        String jsonResponse = result.getResponse().getContentAsString();
        Map responseMap = objectMapper.readValue(jsonResponse, Map.class);
        userAccessToken = (String) ((Map<String, Object>)responseMap).get("data");
    }

    @Test
    @Order(3)
    void testM2MClientCredentialsToken() throws Exception{
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                .param("grant_type", "client_credentials")
                .param("client_id", "test-service-client")
                .param("client_secret", "secret123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.access_token").exists())
                .andReturn();
        String jsonResponse = result.getResponse().getContentAsString();
        Map<String, Object> responseMap = objectMapper.readValue(jsonResponse, Map.class);
        Map<String, Object> dataMap = (Map<String, Object>)responseMap.get("data");
        m2mAccessToken = (String) dataMap.get("access_token");
    }

    @Test
    @Order(4)
    void testScimUSerProvisioning() throws Exception{
        //Required M2M token with admin scope
        Map<String, Object> scimUser = Map.of(
                "schemas", java.util.List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                "userName", "janedoe",
                "emails", java.util.List.of(Map.of("value", "janedoe@iam.com"))
        );

        MvcResult result = mockMvc.perform(post("/scim/v2/Users")
                .header("Authorizartion", "Bearer "+m2mAccessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(scimUser)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userName").value("janedoe"))
                .andReturn();
        String jsonResponse = result.getResponse().getContentAsString();
        Map<String, Object> responseMap = objectMapper.readValue(jsonResponse, Map.class);
        createdUserId = (String) responseMap.get("id");
    }

    @Test
    @Order(5)
    void testTokenIntrospection() throws Exception{
        Map<String, String> introspectRequest = Map.of("token", m2mAccessToken);
        mockMvc.perform(post("/authz/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(introspectRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.active").value(true));
    }
}
