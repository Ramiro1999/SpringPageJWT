package com.curso.springboot.app.auth.filter;

import com.curso.springboot.app.Model.Usuario;
import com.curso.springboot.app.auth.Service.JWTService;
import com.curso.springboot.app.auth.Service.JWTServiceImp;
import com.fasterxml.jackson.databind.ObjectMapper;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


import java.util.HashMap;
import java.util.Map;



public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    private JWTService jwtService;



    public JWTAuthenticationFilter(AuthenticationManager authenticationManager,JWTService jwtService) {
        this.authenticationManager= authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
        this.jwtService=jwtService;
    }

    //se envian los datos via form-data o raw
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {


        String username = obtainUsername(request);
        String password = obtainPassword(request);


        if(username!=null && password !=null){
            logger.info("Username desde request parameter (form-data): " + username);
            logger.info("Password desde request parameter (form-data): " + password);

        }else{
            Usuario usuario = null;
            try {
                usuario = new ObjectMapper().readValue(request.getInputStream(),Usuario.class);
                username=usuario.getUsername();
                password=usuario.getPassword();

                logger.info("Username desde request parameter (raw): " + username);
                logger.info("Password desde request parameter (raw): " + password);

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        username = username.trim();
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password);

        return authenticationManager.authenticate(authToken);
    }

    //una vez autorizado de forma correcta -->

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {


        String token = jwtService.create(authResult);

        response.addHeader(JWTServiceImp.HEADER_STRING,JWTServiceImp.TOKEN_PREFIX + token); //se pasa el token a la cabecera, IMPORTANTE USAR "BEARER ", es un estandar

        //se pasan algunos parametros mas al usuario
        Map<String,Object> body = new HashMap<String,Object>();
        body.put("token",token);
        body.put("user",authResult.getPrincipal());
        body.put("mensaje","ha iniciado sesion con exito!");
        response.getWriter().write(new ObjectMapper().writeValueAsString(body)); //se guarda el contenido en formato json
        response.setStatus(200); //status ok
        response.setContentType("application/json");

        logger.info("secretKey: "+ jwtService.secretKey());

    }

    //en caso de que no sea autorizado de forma correcta -->
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

        Map<String,Object> body = new HashMap<String,Object>();
        body.put("mensaje","Error de autenticación: username o password incorrecto");
        body.put("error",failed.getMessage());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));//se guarda el contenido en formato json
        response.setStatus(401); //status 401
        response.setContentType("application/json");
    }
}
