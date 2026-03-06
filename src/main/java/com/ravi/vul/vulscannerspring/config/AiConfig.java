package com.ravi.vul.vulscannerspring.config;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes a ChatClient backed by whichever vendor Spring AI auto-configured.
 * The active vendor is selected via spring.ai.model.chat (set through LLM_VENDOR
 * env var). Valid values: ollama | openai | anthropic | google-genai.
 */
@Configuration
public class AiConfig {

    @Bean
    public ChatClient chatClient(ChatClient.Builder builder) {
        return builder.build();
    }
}
