package com.curso.springboot.app.auth.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Collection;

public interface JWTService {

    public String create(Authentication auth) throws IOException; //crea el token

    public boolean validate(String token); //valida el token

    public Claims getClaims(String token);

    public String getUsername(String token);

    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException; //obtenemos los roles

    public String resolve(String token); //le quita el Bearer al token


    public String secretKey();

}
