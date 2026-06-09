package br.com.forum_hub.domain.autenticacao;

import br.com.forum_hub.domain.usuario.Usuario;
import br.com.forum_hub.infra.exception.RegraDeNegocioException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    public String gerarToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("chave-secreta");
            return JWT.create()
                    .withIssuer("Forum Hub")
                    .withSubject(usuario.getUsername())
                    .withExpiresAt(expirarEm(30))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RegraDeNegocioException("Erro ao gerar token JWT de acesso!");
        }
    }

    public String gerarRefreshToken(Usuario usuario) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("chave-secreta");
            return JWT.create()
                    .withIssuer("Forum Hub")
                    .withSubject(usuario.getId().toString())
                    .withExpiresAt(expirarEm(120))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RegraDeNegocioException("Erro ao gerar token JWT de acesso!");
        }
    }

    public String verificarTokenEobterSubject(String token) {
        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.HMAC256("chave-secreta");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("Forum Hub")
                    .build();

            decodedJWT = verifier.verify(token);
            return decodedJWT.getSubject();
        } catch (RuntimeException e) {
            throw new RegraDeNegocioException("Erro ao gerar token JWT de acesso!");
        }
    }

    public String verificarRefreshTokenEobterSubject(String token) {
        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.HMAC256("chave-secreta");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("Forum Hub")
                    .build();

            decodedJWT = verifier.verify(token);
            return decodedJWT.getSubject();
        } catch (RuntimeException e) {
            throw new RegraDeNegocioException("Erro ao gerar token JWT de acesso!");
        }

    }

    private Instant expirarEm(int minutos) {
        return LocalDateTime.now().plusMinutes(minutos).toInstant(ZoneOffset.of("-03:00"));
    }

}
