package com.ravi.vul.vulscannerspring.config;

import com.ravi.vul.vulscannerspring.service.McpToolsService;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers VulnHawk tools with the Spring AI MCP server.
 * All @Tool methods in McpToolsService are exposed at /mcp/sse.
 */
@Configuration
public class McpServerConfig {

    @Bean
    public ToolCallbackProvider vulnhawkMcpTools(McpToolsService mcpToolsService) {
        return MethodToolCallbackProvider.builder()
                .toolObjects(mcpToolsService)
                .build();
    }
}
