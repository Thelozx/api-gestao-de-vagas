package br.com.talisfilipe.gestao_vagas.modules.candidate.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.talisfilipe.gestao_vagas.modules.candidate.dto.AuthCandidateResquestDTO;
import br.com.talisfilipe.gestao_vagas.modules.candidate.userCases.AuthCandidateUseCase;

@RestController
@RequestMapping("/candidate")
public class AuthCandidateController {

    @Autowired
    private AuthCandidateUseCase authCandidateUseCase;

    @PostMapping("/auth")
    public ResponseEntity<Object> auth(@RequestBody AuthCandidateResquestDTO authCandidateResquestDTO) {

        try {

            var token = this.authCandidateUseCase.execute(authCandidateResquestDTO);
            return ResponseEntity.ok().body(token);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());

        }

    }

}
