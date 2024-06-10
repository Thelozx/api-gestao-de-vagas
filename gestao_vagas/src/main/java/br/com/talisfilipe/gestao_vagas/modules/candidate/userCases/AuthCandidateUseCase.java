package br.com.talisfilipe.gestao_vagas.modules.candidate.userCases;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.talisfilipe.gestao_vagas.modules.candidate.CandidateRepository;
import br.com.talisfilipe.gestao_vagas.modules.candidate.dto.AuthCandidateResponseDTO;
import br.com.talisfilipe.gestao_vagas.modules.candidate.dto.AuthCandidateResquestDTO;
import jakarta.security.auth.message.AuthException;

@Service
public class AuthCandidateUseCase {

    @Value("${security.token.secret.candidate}")
    private String secrekKey;

    @Autowired
    private CandidateRepository candidateRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthCandidateResponseDTO execute(AuthCandidateResquestDTO AuthCandidateResquestDTO) throws AuthException {
        var candidate = this.candidateRepository.findByUsername(AuthCandidateResquestDTO.username())
                .orElseThrow(() -> {
                    throw new UsernameNotFoundException("Username/Password incorrect");
                });

        var passwordMatches = this.passwordEncoder
                .matches(AuthCandidateResquestDTO.password(), candidate.getPassword());

        if (!passwordMatches) {
            throw new AuthException();
        }

        Algorithm algorithm = Algorithm.HMAC256(secrekKey);
        var expiresIn = Instant.now().plus(Duration.ofHours(2));
        var token = JWT.create()
                .withIssuer("Javagas")
                .withSubject(candidate.getId().toString())
                .withClaim("roles", Arrays.asList("CANDIDATE"))
                .withExpiresAt(expiresIn)
                .sign(algorithm);

        var authCandidateResponseDTO = AuthCandidateResponseDTO.builder()
                .access_token(token)
                .expires_in(expiresIn.toEpochMilli())
                .build();

        return authCandidateResponseDTO;

    }
}
