package org.example.jwtsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.example.jwtsecurity.dto.JoinDTO;
import org.example.jwtsecurity.service.JoinService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }

}
