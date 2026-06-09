package br.com.forum_hub.infra.seguranca;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class ConfiguracoesSeguranca {

    private final FiltroTokenAcesso filtroTokenAcesso;

    public ConfiguracoesSeguranca(FiltroTokenAcesso filtroTokenAcesso) {
        this.filtroTokenAcesso = filtroTokenAcesso;
    }

    @Bean
    public SecurityFilterChain filtroSeguranca(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(
                    req -> req.requestMatchers("/login").permitAll() // permite acesso sem autenticação para endpoints de autenticação
                    .anyRequest().authenticated() // exige autenticação para todos os outros endpoints
            )
            .sessionManagement(sm -> // desabilita a criação de sessões, pois usaremos JWT para autenticação
                sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable()) // desabilita CSRF, pois não usaremos cookies para autenticação
            .addFilterBefore(filtroTokenAcesso, UsernamePasswordAuthenticationFilter.class) // TODO: Incluir essa linha e sua explicação no flashcrd sobre autenticação JWT
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Como desabilitamos a criação de sessões, precisamos expor o AuthenticationManager como um bean para que ele possa ser injetado em outros componentes (como o controller de autenticação)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
