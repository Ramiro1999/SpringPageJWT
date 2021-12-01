package com.curso.springboot.app.auth.filter;


import com.curso.springboot.app.auth.Service.JWTService;

import com.curso.springboot.app.auth.Service.JWTServiceImp;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private JWTService jwtService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        super(authenticationManager);
        this.jwtService=jwtService;
    }

    //cuando el usuario quiere acceder a un recurso, se va a validar ese token que se le asigno.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader(JWTServiceImp.HEADER_STRING); //obtenemos el token

        if (!requiresAuthentication(header)){
            chain.doFilter(request,response); //continuamos con la ejecucion
            return; //nos salimos del filtro
        }

        UsernamePasswordAuthenticationToken authentication = null;
        if(jwtService.validate(header)){ //validamos el token

            authentication= new UsernamePasswordAuthenticationToken(jwtService.getUsername(header),null, jwtService.getRoles(header));
        }
        SecurityContextHolder.getContext().setAuthentication(authentication); //aqui se autentica al usuario dentro del request
        chain.doFilter(request,response); //se continua con la ejecucion

    }
    protected boolean requiresAuthentication(String header){

        if (header == null || !header.startsWith(JWTServiceImp.TOKEN_PREFIX)){
            return false;
        }
            return true;


    }
}
