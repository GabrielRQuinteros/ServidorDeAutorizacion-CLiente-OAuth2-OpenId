package com.gabriel.springboot.security.authserver.auth;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/*
 * Configuración de seguridad en Spring con OAuth2 y OpenID Connect.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /*
     * Filtro de seguridad para el servidor de autorización.
     * Se encarga de gestionar las solicitudes relacionadas con OAuth2 y OpenID Connect.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        // Configurador del servidor de autorización OAuth2
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // Aplica la configuración solo a los endpoints del servidor de autorización
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                // Habilita OpenID Connect (OIDC) por defecto
                                .oidc(Customizer.withDefaults())
                )
                // Exige autenticación en cualquier solicitud
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                // Manejo de excepciones: Redirige a la página de inicio de sesión si no está autenticado
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    /*
     * Configuración de seguridad predeterminada para cualquier otra solicitud no gestionada
     * específicamente por el servidor de autorización.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                // Exige autenticación en todas las solicitudes
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                // Deshabilita la protección CSRF (Cross-Site Request Forgery)
                .csrf((csrf) -> csrf.disable())
                // Habilita el inicio de sesión con un formulario por defecto
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /*
     * Define un servicio de autenticación de usuarios en memoria.
     * Se crea un usuario con nombre "Gabriel" y contraseña "Gabriel1234".
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("Gabriel")
                .password("{noop}Gabriel1234") // {noop} indica que la contraseña no está encriptada
                .roles("USER") // Asigna el rol "USER" a este usuario
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /*
     * Configuración del cliente OAuth2 registrado.
     * Define credenciales y permisos del cliente para la autenticación con OAuth2.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-app")
                .clientSecret("{noop}1234") // {noop} indica que la contraseña no está encriptada
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Soporta código de autorización
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Permite actualizar tokens
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-app") // URI de redirección tras autenticación
                .redirectUri("http://127.0.0.1:8080/authorized") // URI de redirección tras autenticación
                .postLogoutRedirectUri("http://127.0.0.1:8080/") // URI de redirección tras cerrar sesión
                .scope("read")
                .scope("write")
                .scope(OidcScopes.OPENID) // Habilita OpenID Connect
                                          // ||||||||IMPORTANTE||||||||
                                          // OAuth2 base --> Me permite solamente acceder a recursos del usuario.
                                         // OpenID --> Extiende las funcionalidades de OAuth2 para permitir autenticación y acceso a información de perfil.

                .scope(OidcScopes.PROFILE) // Permite acceso a información de perfil
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build()) // Requiere consentimiento del usuario
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    /*
     * Configuración de la clave pública y privada para firmar tokens JWT.
     * Se usa un par de claves RSA.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /*
     * Genera un par de claves RSA para la firma de tokens JWT.
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // Se genera una clave de 2048 bits
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /*
     * Decodificador de tokens JWT basado en las claves generadas.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /*
     * Configuración del servidor de autorización OAuth2.
     * Utiliza valores predeterminados.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}