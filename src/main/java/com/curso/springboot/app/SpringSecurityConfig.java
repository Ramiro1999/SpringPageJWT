package com.curso.springboot.app;


import com.curso.springboot.app.Service.UserService;
import com.curso.springboot.app.auth.Service.JWTService;
import com.curso.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.curso.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.curso.springboot.app.auth.handler.LoginSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

     @Autowired
     private BCryptPasswordEncoder passwordEncoder;

     @Autowired
     private JWTService jwtService;

    @Autowired
    private LoginSuccessHandler successHandler; // sirve para enviar un mensaje de exito cuando el usuario se loguea

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/","/css/**","/js/**","/images/**","/listar","/listar-rest").permitAll()
        	    .antMatchers("/ver/**").hasAnyRole("USER")
                .antMatchers("/uploads/**").hasAnyRole("USER")
                .antMatchers("/form/**").hasAnyRole("ADMIN")
                .antMatchers("/eliminar/**").hasAnyRole("ADMIN")
                .antMatchers("/factura/**").hasAnyRole("ADMIN")
                .antMatchers("/editar/**").hasAnyRole("ADMIN")
                .anyRequest().authenticated()
                /*.and()
                    .formLogin()
                        .successHandler(successHandler)
                        .loginPage("/login")
                    .permitAll()
                .and()
                    .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403")

                 */
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(),jwtService)) //aniadimos el filtro
                .addFilter(new JWTAuthorizationFilter(authenticationManager(),jwtService))
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //se deshabilita el uso de sesion

    }



    @Autowired
    public void configureGlobal (AuthenticationManagerBuilder builder) throws Exception{


        builder.userDetailsService(userService)
                .passwordEncoder(passwordEncoder);


    }



}
