package com.curso.springboot.app.auth.Service;

import com.curso.springboot.app.auth.SimpleGrantedAuthorityMixin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

@Component
public class JWTServiceImp implements JWTService{

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public static final String secretKeyString = new String(SECRET_KEY.getEncoded(), StandardCharsets.UTF_16); //obtenemos la secretkey

    public static final long EXPIRATION_DATE =  3600000*4;

    public static final String TOKEN_PREFIX = "Bearer ";

    public static final String HEADER_STRING = "Authorization";
    @Override
    public String create(Authentication auth) throws IOException {
        String username = ((User) auth.getPrincipal()).getUsername();

        Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles)); //Pasamos los roles a json con ObjectMapper
        //creando el token
        String token = Jwts.builder()
                .setClaims(claims) //pasamos los roles al jwt
                .setSubject(username) //nombre del usuario
                .signWith(SECRET_KEY) //se firma con una clave secreta
                .setIssuedAt(new Date()) //fecha de creacion
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE)) //cuanto va a durar el token,(expiracion) 3600000 es una hora
                .compact();
        return token;
    }

    @Override
    public boolean validate(String token) { //este metodo va a validar la firma del token
        try {
           getClaims(token);
           return true;
        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

    @Override
    public Claims getClaims(String token) {
       Claims claims = Jwts.parserBuilder()  //aqui se van a guardar el nombre de usuario, los roles etc
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(resolve(token)) //obtenemos el token
                .getBody();
        return claims;
    }

    @Override
    public String getUsername(String token) {
       return getClaims(token).getSubject();
    }

    @Override
    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
       Object roles = getClaims(token).get("authorities");
        Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
                .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));  //lo tenemos que convertir a una coleccion del tipo grantedAuthorities
        return authorities;
    }

    @Override
    public String resolve(String token) {
        if(token!=null && token.startsWith(TOKEN_PREFIX)) {
            return token.replace(TOKEN_PREFIX, "");
        }
        return null;
    }

    @Override
    public String secretKey() {
        return secretKeyString;
    }
}
