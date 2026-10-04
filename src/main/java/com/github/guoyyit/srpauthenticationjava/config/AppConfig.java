package com.github.guoyyit.srpauthenticationjava.config;

import com.github.guoyyit.srpauthenticationjava.auth.AuditService;
import com.github.guoyyit.srpauthenticationjava.auth.LockoutService;
import com.github.guoyyit.srpauthenticationjava.auth.ReplayGuard;
import com.github.guoyyit.srpauthenticationjava.auth.SrpServerService;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpCrypto;
import com.github.guoyyit.srpauthenticationjava.crypto.SrpGroup;
import com.github.guoyyit.srpauthenticationjava.session.SessionManager;
import com.github.guoyyit.srpauthenticationjava.store.JsonFileStore;
import com.github.guoyyit.srpauthenticationjava.store.RegistrationStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

@Configuration
@EnableConfigurationProperties(SrpProperties.class)
public class AppConfig {

    @Bean
    public JsonFileStore jsonFileStore(SrpProperties properties) {
        return new JsonFileStore(Path.of(properties.getDataDir()));
    }

    @Bean
    public RegistrationStore registrationStore(JsonFileStore fileStore) {
        return new RegistrationStore(fileStore);
    }

    @Bean
    public AuditService auditService(JsonFileStore fileStore) {
        return new AuditService(fileStore);
    }

    @Bean
    public LockoutService lockoutService(JsonFileStore fileStore, SrpProperties properties) {
        return new LockoutService(fileStore, properties);
    }

    @Bean
    public SrpCrypto srpCrypto(SrpProperties properties) {
        return new SrpCrypto(SrpGroup.rfc5054_2048(),
                properties.getDigestAlgorithm(), properties.getIterations());
    }

    @Bean
    public ReplayGuard replayGuard(JsonFileStore fileStore, SrpCrypto crypto,
                                   SrpProperties properties) {
        return new ReplayGuard(fileStore, crypto,
                properties.getHandshakeTtlSeconds() * 1000L);
    }

    @Bean
    public SessionManager sessionManager(JsonFileStore fileStore, SrpProperties properties) {
        return new SessionManager(fileStore,
                properties.getSessionTtlSeconds() * 1000L);
    }

    @Bean
    public SrpServerService srpServerService(RegistrationStore registrationStore,
                                             SrpProperties properties,
                                             LockoutService lockoutService,
                                             ReplayGuard replayGuard,
                                             AuditService auditService,
                                             SessionManager sessionManager) {
        return new SrpServerService(registrationStore, properties, lockoutService,
                replayGuard, auditService, sessionManager);
    }
}
