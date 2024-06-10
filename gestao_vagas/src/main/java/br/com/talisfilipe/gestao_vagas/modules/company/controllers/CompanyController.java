package br.com.talisfilipe.gestao_vagas.modules.company.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import br.com.talisfilipe.gestao_vagas.modules.company.entities.CompanyEntity;
import br.com.talisfilipe.gestao_vagas.modules.company.useCases.CreatedCompanyUseCase;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/company")
public class CompanyController {

    @Autowired
    private CreatedCompanyUseCase createdCompanyUseCase;

    @PostMapping("/")
    public ResponseEntity<Object> create(@Valid @RequestBody CompanyEntity companyEntity) {
        try {
            var result = this.createdCompanyUseCase.execute(companyEntity);
            return ResponseEntity.ok().body(result);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(e.getMessage());
            
        }
    }
}
