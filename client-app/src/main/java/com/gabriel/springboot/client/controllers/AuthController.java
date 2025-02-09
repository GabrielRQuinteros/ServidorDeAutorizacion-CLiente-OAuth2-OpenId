package com.gabriel.springboot.client.controllers;


import com.gabriel.springboot.client.models.Message;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class AuthController {

    @GetMapping("/list")
    List<Message> list() {
        return Collections.singletonList( new Message("List Message" ) );
    }

    @PostMapping("/create")
    Message create( @RequestBody Message message ) {
        System.out.println( "Mensaje Guardado: " + message.getText() );
        return message;
    }

    @GetMapping("/authorized")
    public Map<String, String> authorized( @RequestParam String code ) {
        return Collections.singletonMap("code", code );
    }

}
